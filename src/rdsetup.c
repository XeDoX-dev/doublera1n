/*
 * rdsetup - one-shot dual-boot setup. Runs in place of restored_external on the stock restore ramdisk
 * booted SEP-less from pwned DFU.
 *
 * Install (default):
 *   1. list every APFS volume (BSD name, name, role) via IOKit
 *   2. if no volume named "DataB" exists: newfs_apfs -A -v DataB <container>   (unencrypted, no role)
 *      -> only ADDS a volume to the existing container; nothing existing is touched
 *   3. mount the stock System volume read-only on /mnt1, DataB on /mnt2; print "SYSBUILD <build>" (the host tool
 *      checks it against its version profile)
 *   4. on a fresh DataB, copy the System volume's /private/var template into it (including staged_system_apps)
 *   5. mount Preboot READ-ONLY and dump every <bootManifestHash>/System/Library/Caches/apticket.der to the console
 *      (hex, CRC32 per line, 6 passes) and to DataB:/jb/ (OS B images must be signed with it)
 *   6. write the log to DataB, unmount, print SETUP DONE
 * Remove (mode file /usr/local/share/dualboot/mode = "remove"): after strict checks, delete our
 *   /private/preboot/Cryptexes/ob directory and the DataB volume (APFSVolumeDelete).
 * USB modes wait for a token-gated start request and return the result over a loopback socket.
 *
 * Install never writes to any volume other than the one it created (or found) named DataB; remove deletes only
 * DataB and Preboot:/Cryptexes/ob.
 * Build for macOS with -DHOST_TEST to dry-run the volume listing plus the ticket dump (1 arg) or the template copy
 * (2 args) against a mounted image.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <spawn.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <copyfile.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <dirent.h>
#include <ctype.h>
#include <dlfcn.h>
#include <removefile.h>

#include "rdsetup_usb.h"

typedef unsigned int io_object_t, io_iterator_t, io_service_t, kern_return_t_;
extern const unsigned int kIOMainPortDefault;
CFMutableDictionaryRef IOServiceMatching(const char *name);
int IOServiceGetMatchingServices(unsigned int port, CFDictionaryRef matching, io_iterator_t *it);
io_object_t IOIteratorNext(io_iterator_t it);
CFTypeRef IORegistryEntryCreateCFProperty(io_object_t e, CFStringRef key, CFAllocatorRef a, unsigned int opts);
int IORegistryEntryGetName(io_object_t e, char name[128]);
int IOObjectRelease(io_object_t o);

#define VOLNAME "DataB"
extern char **environ;

static char logbuf[RDUSB_MAX_LOG];
static size_t loglen;
static int usb_mode;
static unsigned char usb_ticket[RDUSB_MAX_TICKET];
static size_t usb_ticket_size;
static char usb_ticket_dir[RDUSB_DIR_SIZE];
static unsigned char usb_ticket_digest[RDUSB_DIGEST_SIZE];

static void say(const char *fmt, ...) {
    char line[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(line, sizeof line, fmt, ap); va_end(ap);
    fprintf(stdout, "[rdsetup] %s\n", line); fflush(stdout);
    int n = snprintf(logbuf + loglen, sizeof logbuf - loglen, "%s\n", line);
    if (n > 0 && loglen + n < sizeof logbuf) loglen += n;
}

static int run(const char *const argv[]) {
    char cmd[512] = "";
    for (int i = 0; argv[i]; i++) { strlcat(cmd, argv[i], sizeof cmd); strlcat(cmd, " ", sizeof cmd); }
    say("run: %s", cmd);
    pid_t pid; int st = 0;
    int r = posix_spawn(&pid, argv[0], NULL, NULL, (char *const *)argv, environ);
    if (r) { say("  posix_spawn failed: %d (%s)", r, strerror(r)); return -1; }
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
    say("  -> exit %d", rc);
    return rc;
}

static void cfstr(CFTypeRef v, char *out, size_t n) {
    out[0] = 0;
    if (!v) { strlcpy(out, "-", n); return; }
    if (CFGetTypeID(v) == CFStringGetTypeID()) CFStringGetCString(v, out, n, kCFStringEncodingUTF8);
    else if (CFGetTypeID(v) == CFNumberGetTypeID()) { long long x = 0; CFNumberGetValue(v, kCFNumberLongLongType, &x); snprintf(out, n, "%lld", x); }
    else if (CFGetTypeID(v) == CFArrayGetTypeID()) {
        for (CFIndex i = 0; i < CFArrayGetCount(v); i++) {
            char t[64]; cfstr(CFArrayGetValueAtIndex(v, i), t, sizeof t);
            if (i) strlcat(out, ",", n);
            strlcat(out, t, n);
        }
    } else if (CFGetTypeID(v) == CFBooleanGetTypeID()) strlcpy(out, CFBooleanGetValue(v) ? "true" : "false", n);
    else strlcpy(out, "?", n);
}

/* lists volumes; returns number of volumes, fills bsd of the one named VOLNAME (if any) */
static char sys_bsd[64]; static int sys_count;
static char pre_bsd[64]; static int pre_count;
static char named_role[32];
static int list_volumes(char *found_bsd, size_t n, int *count_named) {
    io_iterator_t it = 0; int cnt = 0; *count_named = 0; if (found_bsd) found_bsd[0] = 0; sys_bsd[0] = 0; sys_count = 0; pre_bsd[0] = 0; pre_count = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("AppleAPFSVolume"), &it)) { say("IOServiceGetMatchingServices failed"); return -1; }
    io_object_t e;
    while ((e = IOIteratorNext(it))) {
        char bsd[64], full[128], role[128], rolev[32], regname[128] = "";
        CFTypeRef v;
        v = IORegistryEntryCreateCFProperty(e, CFSTR("BSD Name"), NULL, 0); cfstr(v, bsd, sizeof bsd); if (v) CFRelease(v);
        v = IORegistryEntryCreateCFProperty(e, CFSTR("FullName"), NULL, 0); cfstr(v, full, sizeof full); if (v) CFRelease(v);
        v = IORegistryEntryCreateCFProperty(e, CFSTR("Role"), NULL, 0); cfstr(v, role, sizeof role); if (v) CFRelease(v);
        v = IORegistryEntryCreateCFProperty(e, CFSTR("RoleValue"), NULL, 0); cfstr(v, rolev, sizeof rolev); if (v) CFRelease(v);
        IORegistryEntryGetName(e, regname);
        say("  volume %-10s name=%-16s full=%-16s role=%s (%s)", bsd, regname, full, rolev, role);
        if (!strcmp(full, VOLNAME) || !strcmp(regname, VOLNAME)) {
            (*count_named)++;
            if (found_bsd) strlcpy(found_bsd, bsd, n);
            strlcpy(named_role, rolev, sizeof named_role);
        }
        if (!strcmp(rolev, "1") || !strcmp(role, "System")) { sys_count++; strlcpy(sys_bsd, bsd, sizeof sys_bsd); }
        if (!strcmp(rolev, "16") || !strcmp(role, "Preboot")) { pre_count++; strlcpy(pre_bsd, bsd, sizeof pre_bsd); }
        cnt++;
        IOObjectRelease(e);
    }
    IOObjectRelease(it);
    return cnt;
}

static long copied_files, skipped;
static int skip_staged = 0;   /* staged_system_apps is copied too: OS B installs them with SystemAppMigrator (jbinit/sysapps.m) */
static int copy_cb(int what, int stage, copyfile_state_t s, const char *src, const char *dst, void *ctx) {
    (void)s; (void)dst; (void)ctx;
    if (stage == COPYFILE_START && what == COPYFILE_RECURSE_DIR) {
        const char *b = strrchr(src, '/'); b = b ? b + 1 : src;
        if (skip_staged && !strcmp(b, "staged_system_apps")) { skipped++; return COPYFILE_SKIP; }
    }
    if (stage == COPYFILE_FINISH && what == COPYFILE_RECURSE_FILE) copied_files++;
    if (stage == COPYFILE_ERR) { say("  copy error %s: %s", src, strerror(errno)); return COPYFILE_CONTINUE; }
    return COPYFILE_CONTINUE;
}

static int copy_template(const char *from, const char *to) {
    say("copy template %s -> %s", from, to);
    copyfile_state_t st = copyfile_state_alloc();
    copyfile_state_set(st, COPYFILE_STATE_STATUS_CB, (const void *)copy_cb);
    int r = copyfile(from, to, st, COPYFILE_ALL | COPYFILE_RECURSIVE | COPYFILE_NOFOLLOW);
    copyfile_state_free(st);
    say("  copyfile -> %d (%s), files=%ld, skipped dirs=%ld", r, r ? strerror(errno) : "ok", copied_files, skipped);
    return r;
}

static int wait_path(const char *p, int secs) {
    struct stat sb;
    for (int i = 0; i < secs; i++) { if (!stat(p, &sb)) return 0; if (i % 5 == 0) say("waiting for %s", p); sleep(1); }
    return -1;
}


static unsigned crc32b(const unsigned char *p, size_t n) {
    unsigned c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) { c ^= p[i]; for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1))); }
    return ~c;
}

static int write_file(const char *path, const void *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int complete = fwrite(data, 1, size, f) == size;
    return fclose(f) == 0 && complete ? 0 : -1;
}

static int save_ticket(const char *dir, const char *manifest, const unsigned char *data, size_t size) {
    char path[512];
    snprintf(path, sizeof path, "%s/apticket-%.16s.der", dir, manifest);
    if (write_file(path, data, size)) {
        say("cannot save %s", path);
        return -1;
    }
    say("saved %s", path);
    return 0;
}

/* dump every Preboot/<96 hex>/System/Library/Caches/apticket.der; returns number dumped */
static int dump_tickets(const char *preboot, const char *save_dir) {
    DIR *dp = opendir(preboot); if (!dp) { say("opendir %s: %s", preboot, strerror(errno)); return 0; }
    struct dirent *de; int found = 0;
    while ((de = readdir(dp))) {
        size_t L = strlen(de->d_name); int hex = (L == 96);
        for (size_t i = 0; hex && i < L; i++) hex = isxdigit((unsigned char)de->d_name[i]);
        if (!hex) continue;
        char path[512]; snprintf(path, sizeof path, "%s/%s/System/Library/Caches/apticket.der", preboot, de->d_name);
        int fd = open(path, O_RDONLY); if (fd < 0) { say("TICKET %s: %s", path, strerror(errno)); continue; }
        static unsigned char buf[RDUSB_MAX_TICKET];
        struct stat st = {0};
        if (usb_mode && (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
                         st.st_size <= 0 || st.st_size > (off_t)sizeof buf)) {
            close(fd);
            say("TICKET has an invalid size or type at %s", path);
            closedir(dp);
            return -1;
        }
        ssize_t n = read(fd, buf, sizeof buf); close(fd);
        if (n <= 0 || (usb_mode && n != st.st_size)) {
            say("TICKET read %s failed", path);
            if (usb_mode) {
                closedir(dp);
                return -1;
            }
            continue;
        }
        if (usb_mode) {
            if (usb_ticket_size && (usb_ticket_size != (size_t)n || memcmp(usb_ticket, buf, (size_t)n))) {
                say("multiple distinct installed tickets; cannot safely select one for USB setup");
                closedir(dp);
                return -1;
            }
            if (!usb_ticket_size) {
                usb_ticket_size = (size_t)n;
                memcpy(usb_ticket, buf, usb_ticket_size);
                memcpy(usb_ticket_dir, de->d_name, sizeof usb_ticket_dir);
                CC_SHA384(buf, (CC_LONG)n, usb_ticket_digest);
                say("selected installed APTicket %.96s (%zd bytes)", usb_ticket_dir, n);
            }
            found++;
            continue;
        }
        unsigned char md[CC_SHA384_DIGEST_LENGTH]; CC_SHA384(buf, (CC_LONG)n, md);
        char mh[2 * CC_SHA384_DIGEST_LENGTH + 1]; for (int i = 0; i < CC_SHA384_DIGEST_LENGTH; i++) sprintf(mh + 2 * i, "%02X", md[i]);
        say("TICKET dir=%s len=%zd sha384=%s crc=%08x", de->d_name, n, mh, crc32b(buf, n));
        for (int pass = 0; pass < 6; pass++)
            for (ssize_t off = 0; off < n; off += 48) {
                size_t m = (size_t)(n - off) < 48 ? (size_t)(n - off) : 48; char hx[97];
                for (size_t i = 0; i < m; i++) sprintf(hx + 2 * i, "%02x", buf[off + i]);
                fprintf(stdout, "TKT %05zx %s %08x\n", (size_t)off, hx, crc32b(buf + off, m)); fflush(stdout);
                usleep(4000);
            }
        say("TICKET END %s", mh);
        if (save_dir) save_ticket(save_dir, de->d_name, buf, (size_t)n);
        found++;
    }
    closedir(dp);
    return found;
}

#ifdef HOST_TEST
int main(int argc, char **argv) {
    int named; char bsd[64];
    say("HOST TEST: volumes"); list_volumes(bsd, sizeof bsd, &named);
    say("named %s: %d (%s)", VOLNAME, named, bsd);
    if (argc == 2) return dump_tickets(argv[1], NULL) > 0 ? 0 : 1;
    if (argc > 2) return copy_template(argv[1], argv[2]) ? 1 : 0;
    return 0;
}
#else
static int remove_mode;
static int usb_listener = -1;
static unsigned char usb_token[RDUSB_TOKEN_SIZE];
static char usb_expected_build[64];

static void finish(int ok) {
    if (remove_mode) say(ok ? "===== REMOVE DONE =====" : "===== REMOVE FAILED =====");
    else say(ok ? "===== SETUP DONE =====" : "===== SETUP FAILED =====");
    if (usb_listener >= 0) {
        struct rdusb_report report = {
            logbuf, loglen, usb_ticket, usb_ticket_size, usb_ticket_dir, usb_ticket_digest,
        };
        rdusb_serve_result(usb_listener, usb_token, ok, &report);
        close(usb_listener);
    }
    for (;;) sleep(3600);   /* leave the result on screen; user force-reboots into stock iOS */
}

static void print_sysbuild(const char *sysroot, char *build, size_t build_size) {
    char p[256]; snprintf(p, sizeof p, "%s/System/Library/CoreServices/SystemVersion.plist", sysroot);
    CFURLRef u = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)p, strlen(p), false);
    CFReadStreamRef rs = u ? CFReadStreamCreateWithFile(NULL, u) : NULL;
    if (rs && CFReadStreamOpen(rs)) {
        CFPropertyListRef pl = CFPropertyListCreateWithStream(NULL, rs, 0, kCFPropertyListImmutable, NULL, NULL);
        if (pl && CFGetTypeID(pl) == CFDictionaryGetTypeID()) {
            char b[64], v[64];
            cfstr(CFDictionaryGetValue(pl, CFSTR("ProductBuildVersion")), b, sizeof b);
            cfstr(CFDictionaryGetValue(pl, CFSTR("ProductVersion")), v, sizeof v);
            if (build) strlcpy(build, b, build_size);
            say("SYSBUILD %s SYSVER %s", b, v);
        }
        if (pl) CFRelease(pl);
        CFReadStreamClose(rs);
    } else say("SYSBUILD ? (cannot read %s)", p);
    if (rs) CFRelease(rs);
    if (u) CFRelease(u);
}

static int read_mode(void) {
    char m[32] = {0};
    int fd = open("/usr/local/share/dualboot/mode", O_RDONLY);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    ssize_t n = read(fd, m, sizeof m - 1);
    close(fd);
    if (n <= 0) return -1;
    m[strcspn(m, "\r\n")] = 0;
    if (!strcmp(m, "install")) return 0;
    if (!strcmp(m, "remove")) return 1;
    if (strcmp(m, "install-usb") && strcmp(m, "remove-usb")) return -1;
    usb_mode = 1;
    return !strcmp(m, "remove-usb");
}

static int read_usb_config(void) {
    FILE *f = fopen("/usr/local/share/dualboot/usb-token", "rb");
    if (!f) return -1;
    size_t n = fread(usb_token, 1, sizeof usb_token, f);
    int valid = n == sizeof usb_token && fgetc(f) == EOF && !ferror(f);
    fclose(f);
    if (!valid) return -1;
    f = fopen("/usr/local/share/dualboot/usb-build", "r");
    if (!f) return -1;
    valid = fgets(usb_expected_build, sizeof usb_expected_build, f) != NULL;
    fclose(f);
    usb_expected_build[strcspn(usb_expected_build, "\r\n")] = 0;
    return valid && usb_expected_build[0] ? 0 : -1;
}

static int mount_read_only(const char *bsd, const char *mountpoint) {
    char dev[80];
    snprintf(dev, sizeof dev, "/dev/%s", bsd);
    const char *argv[] = { "/sbin/mount_apfs", "-o", "ro", dev, mountpoint, NULL };
    return run(argv);
}

static int usb_install_preflight(void) {
    int named;
    if (list_volumes(NULL, 0, &named) < 1 || sys_count != 1 || pre_count != 1 || named > 1) {
        say("USB setup requires one System volume, one Preboot volume, and at most one DataB");
        return -1;
    }
    char build[64] = "";
    if (mount_read_only(sys_bsd, "/mnt1")) return -1;
    print_sysbuild("/mnt1", build, sizeof build);
    if (unmount("/mnt1", 0)) {
        say("could not unmount System after USB pre-check");
        return -1;
    }
    if (strcmp(build, usb_expected_build)) {
        say("stock iOS build %s differs from expected build %s", build[0] ? build : "?", usb_expected_build);
        return -1;
    }
    if (mount_read_only(pre_bsd, "/mnt3")) return -1;
    int tickets = dump_tickets("/mnt3", NULL);
    if (unmount("/mnt3", 0)) {
        say("could not unmount Preboot after USB pre-check");
        return -1;
    }
    if (tickets < 1) {
        say("could not select an installed APTicket for USB setup");
        return -1;
    }
    return 0;
}

/* remove: Preboot:/Cryptexes/ob (ours) + the DataB volume. Refuses unless there is exactly one System volume,
   exactly one volume named DataB, it sits in the System container and it has no APFS role. */
static int do_remove(void) {
    int named; char bsd[64];
    say("APFS volumes:");
    if (list_volumes(bsd, sizeof bsd, &named) < 1) { say("no volumes listed"); return -1; }
    if (sys_count != 1) { say("expected exactly one System-role volume, found %d - refusing", sys_count); return -1; }
    char cont[64]; strlcpy(cont, sys_bsd, sizeof cont); char *sl = strrchr(cont, 's'); if (sl && sl != cont) *sl = 0;
    if (named == 0) { say("no %s volume - nothing to delete", VOLNAME); }
    else if (named > 1) { say("more than one %s volume - refusing", VOLNAME); return -1; }
    else {
        if (strncmp(bsd, cont, strlen(cont)) || bsd[strlen(cont)] != 's') { say("%s (%s) not in the System container %s - refusing", VOLNAME, bsd, cont); return -1; }
        if (named_role[0] && strcmp(named_role, "0") && strcmp(named_role, "-")) { say("%s has APFS role %s - refusing", VOLNAME, named_role); return -1; }
        if (!strcmp(bsd, sys_bsd) || !strcmp(bsd, pre_bsd)) { say("%s resolves to a stock volume - refusing", VOLNAME); return -1; }
    }
    /* our Preboot files (shared with stock iOS: only the directory the tool created) */
    if (pre_count == 1) {
        char predev[80]; snprintf(predev, sizeof predev, "/dev/%s", pre_bsd);
        const char *m3[] = { "/sbin/mount_apfs", predev, "/mnt3", NULL };
        if (run(m3) == 0) {
            struct stat sb;
            if (stat("/mnt3/Cryptexes/ob", &sb) == 0) {
                int r = removefile("/mnt3/Cryptexes/ob", NULL, REMOVEFILE_RECURSIVE);
                say("removefile Preboot:/Cryptexes/ob -> %d (%s)", r, r ? strerror(errno) : "ok");
            } else say("Preboot:/Cryptexes/ob not present");
            sync();
            say("unmount /mnt3 -> %d", unmount("/mnt3", 0));
        } else say("cannot mount Preboot - its ob directory stays (harmless for stock iOS)");
    }
    if (named == 1) {
        void *h = dlopen("/System/Library/PrivateFrameworks/APFS.framework/APFS", RTLD_NOW);
        int (*del)(const char *) = h ? (int (*)(const char *))dlsym(h, "APFSVolumeDelete") : NULL;
        if (!del) { say("APFSVolumeDelete unavailable (%s)", dlerror()); return -1; }
        say("APFSVolumeDelete(%s) ...", bsd);
        int r = del(bsd);
        say("APFSVolumeDelete -> 0x%x", r);
        if (r) return -1;
        sleep(2);
        say("APFS volumes after:");
        list_volumes(bsd, sizeof bsd, &named);
        if (named) { say("%s still listed", VOLNAME); return -1; }
    }
    return 0;
}

static int do_install(void) {
    int named; char bsd[64];
    say("APFS volumes before:");
    int before = list_volumes(bsd, sizeof bsd, &named);
    if (before < 1) { say("no volumes listed"); return -1; }
    if (named > 1) { say("more than one %s volume - refusing to continue", VOLNAME); return -1; }
    if (sys_count != 1) { say("expected exactly one System-role volume, found %d - refusing", sys_count); return -1; }
    char cont[64]; strlcpy(cont, sys_bsd, sizeof cont); char *sl = strrchr(cont, 's'); if (sl && sl != cont) *sl = 0;
    say("stock System volume: %s (container %s)", sys_bsd, cont);
    if (named == 0) {
        const char *nf[] = { "/sbin/newfs_apfs", "-A", "-v", VOLNAME, "/dev/disk0s1", NULL };
        if (run(nf) != 0) { say("newfs_apfs failed"); return -1; }
        sleep(2);
        say("APFS volumes after:");
        list_volumes(bsd, sizeof bsd, &named);
        if (named != 1 || !bsd[0]) { say("new volume not found"); return -1; }
    } else say("%s already exists as %s - reusing it", VOLNAME, bsd);
    if (strncmp(bsd, cont, strlen(cont)) || bsd[strlen(cont)] != 's') { say("%s (%s) is not in the System container %s - refusing", VOLNAME, bsd, cont); return -1; }

    char dev[80]; snprintf(dev, sizeof dev, "/dev/%s", bsd);
    say("%s = %s", VOLNAME, dev);
    char sysdev[80]; snprintf(sysdev, sizeof sysdev, "/dev/%s", sys_bsd);
    const char *m1[] = { "/sbin/mount_apfs", "-o", "ro", sysdev, "/mnt1", NULL };
    const char *m2[] = { "/sbin/mount_apfs", dev, "/mnt2", NULL };
    if (run(m1) != 0) { say("cannot mount System ro"); return -1; }
    if (run(m2) != 0) { say("cannot mount %s", VOLNAME); return -1; }
    struct stat sb;
    if (stat("/mnt1/private/var/mobile", &sb)) { say("/mnt1/private/var/mobile missing - wrong System volume?"); return -1; }
    print_sysbuild("/mnt1", NULL, 0);
    int cr = 0, fresh = stat("/mnt2/dualboot-setup.log", &sb) != 0;
    if (fresh) cr = copy_template("/mnt1/private/var/", "/mnt2/");
    else say("%s already set up - template copy skipped", VOLNAME);
    mkdir("/mnt2/jb", 0755);
    if (usb_mode) {
        if (cr == 0 && save_ticket("/mnt2/jb", usb_ticket_dir, usb_ticket, usb_ticket_size)) cr = -1;
    } else if (pre_count != 1) { say("expected exactly one Preboot volume, found %d", pre_count); cr = -1; }
    else {
        char predev[80]; snprintf(predev, sizeof predev, "/dev/%s", pre_bsd);
        const char *m3[] = { "/sbin/mount_apfs", "-o", "ro", predev, "/mnt3", NULL };
        if (run(m3) != 0) { say("cannot mount Preboot ro"); cr = -1; }
        else {
            int t = dump_tickets("/mnt3", "/mnt2/jb");
            say("tickets dumped: %d", t);
            if (t < 1) cr = -1;
            say("unmount /mnt3 -> %d", unmount("/mnt3", 0));
        }
    }
    if (usb_mode && fresh && cr == 0) {
        const char *tmp = "/mnt2/dualboot-setup.log.tmp";
        if (write_file(tmp, logbuf, loglen) || rename(tmp, "/mnt2/dualboot-setup.log")) {
            unlink(tmp);
            say("could not record completed DataB setup");
            cr = -1;
        }
    } else {
        write_file(fresh && !usb_mode ? "/mnt2/dualboot-setup.log" : "/mnt2/dualboot-fetch.log", logbuf, loglen);
    }
    sync();
    say("unmount /mnt2 -> %d", unmount("/mnt2", 0));
    say("unmount /mnt1 -> %d", unmount("/mnt1", 0));
    say("%s device: %s", VOLNAME, dev);
    return cr;
}

int main(void) {
    remove_mode = read_mode();
    if (remove_mode < 0) { say("invalid setup mode"); finish(0); }
    say("===== dualboot setup ramdisk v3 (%s) =====", remove_mode ? "REMOVE" : "INSTALL");
    if (usb_mode) {
        if (read_usb_config()) { say("invalid USB setup configuration"); finish(0); }
        usb_listener = rdusb_open();
        if (usb_listener < 0) { say("cannot open USB setup service: %s", strerror(errno)); finish(0); }
        say("USB setup service ready, waiting for the Mac");
        if (rdusb_wait_start(usb_listener, usb_token, 180)) {
            say("USB setup received no start request");
            finish(0);
        }
    }
    if (wait_path("/dev/disk0s1", 60)) { say("/dev/disk0s1 not found"); finish(0); }
    sleep(3);
    if (usb_mode && !remove_mode && usb_install_preflight()) finish(0);
    finish((remove_mode ? do_remove() : do_install()) == 0);
    return 0;
}
#endif
