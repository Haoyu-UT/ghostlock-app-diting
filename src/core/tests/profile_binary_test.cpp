/* Host test for the binary profile transport shared with Kotlin (wire v2:
 * object sections, presence by key occurrence, exact values).
 *
 * Black box: round trips and rejected vectors through parse/serialize.
 * White box: a local builder injects anything (unknown keys, other sections,
 * duplicates, truncations) and pins the header bytes. */

#include "profile/binary.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace ghostlock;

namespace {
    /* FNV-1a over the canonical schema stream for the vector in the digest
     * block. Asserted with the same value in the Kotlin test
     * (profile-core `NativeProfileDigestTest`), which is what makes the two
     * implementations a checked contract rather than two hopeful copies. */
    constexpr uint64_t kGoldenSchemaDigest = 0xcc8fc4e3d6a4eadfull;

    void put_u16(std::string &out, uint16_t value) {
        out.push_back(static_cast<char>(value & 0xff));
        out.push_back(static_cast<char>((value >> 8) & 0xff));
    }

    void put_u32(std::string &out, uint32_t value) {
        for (int i = 0; i < 4; i++) out.push_back(static_cast<char>((value >> (8 * i)) & 0xff));
    }

    void put_u64(std::string &out, uint64_t value) {
        for (int i = 0; i < 8; i++) out.push_back(static_cast<char>((value >> (8 * i)) & 0xff));
    }

    struct Entry {
        std::string key;
        int64_t value;
    };

    struct Section {
        std::string name;
        std::vector<Entry> entries;
    };

    /* Builds one v2 document byte by byte so tests can inject anything. */
    std::string build_doc(uint8_t route, const std::string &release,
                          const std::vector<Section> &sections,
                          uint16_t frontend = binary_profile::kFrontendRootChild,
                          uint16_t backend = binary_profile::kBackendCve202643499) {
        std::string out;
        put_u32(out, binary_profile::kMagic);
        put_u16(out, binary_profile::kVersion);
        put_u16(out, frontend);
        put_u16(out, backend);
        put_u16(out, route);
        put_u16(out, static_cast<uint16_t>(release.size()));
        put_u16(out, 0); /* reserved: header is 16 bytes */
        out += release;
        put_u16(out, static_cast<uint16_t>(sections.size()));
        for (const Section &section : sections) {
            out.push_back(static_cast<char>(section.name.size()));
            out += section.name;
            put_u32(out, static_cast<uint32_t>(section.entries.size()));
            for (const Entry &entry : section.entries) {
                out.push_back(static_cast<char>(entry.key.size()));
                out += entry.key;
                put_u64(out, static_cast<uint64_t>(entry.value));
            }
        }
        return out;
    }

    int32_t parse_doc(const std::string &doc, profile::kernel_offsets *out, char *release,
                      size_t release_cap) {
        return binary_profile::parse(std::string_view(doc.data(), doc.size()), out, release,
                                     release_cap);
    }

    int32_t round_trip(const profile::kernel_offsets &values, profile::kernel_offsets *parsed,
                       char *release, size_t release_cap) {
        char buffer[8192];
        const int32_t size = binary_profile::serialize(&values, buffer, sizeof(buffer));
        if (size <= 0) return -1;
        return binary_profile::parse(std::string_view(buffer, static_cast<size_t>(size)), parsed,
                                     release, release_cap);
    }
} // namespace

int32_t main(void) {
    char release[64] = {0};
    profile::kernel_offsets parsed = {};

    /* ---- Black box: round trips through the public API. ---- */
    profile::kernel_offsets values = {};
    values.uname_r = "6.6.77-transport-test";
    values.route = ghostlock::profile::kRouteMulticastWaiter;
    values.meta.kernel_major = 6;
    values.meta.recommend_shizuku = 1;
    values.meta.fallback_route = ghostlock::profile::kRouteSelectStack;
    values.task.prio = 132;
    values.task.real_cred = 0x12345678;
    values.credential.copy_size = 0x88;
    values.credential.caps_value = 0xffffffffffffffffULL;
    values.offsets.init_task = 0x20dc000;
    values.offsets.slide_boot_id = 0x2336600;
    values.misc.compact_waiter = 1;
    values.misc.kernelsnitch_collisions = 4;
    values.misc.mm_struct_sz = 0x400;
    values.execution.w1_attempts = 15;
    values.execution.race_route_done_timeout_ms = 300000;
    values.execution.handoff_enforce_poll_interval_ms = 100;
    values.geometry.mcast_waiter_off = 96;
    values.geometry.mcast_buffer_size = 512;

    assert(round_trip(values, &parsed, release, sizeof(release)) == 0);
    assert(strcmp(release, values.uname_r) == 0);
    assert(strcmp(parsed.uname_r, values.uname_r) == 0);
    assert(parsed.meta.kernel_major == 6);
    assert(parsed.meta.recommend_shizuku == 1);
    assert(parsed.route == ghostlock::profile::kRouteMulticastWaiter);
    assert(parsed.meta.fallback_route == ghostlock::profile::kRouteSelectStack);
    assert(parsed.task.prio == 132);
    assert(parsed.task.real_cred == 0x12345678);
    assert(parsed.credential.copy_size == 0x88);
    assert(parsed.credential.caps_value == 0xffffffffffffffffULL);
    assert(parsed.offsets.init_task == 0x20dc000);
    assert(parsed.offsets.slide_boot_id == 0x2336600);
    assert(parsed.misc.compact_waiter.value_or(0) == 1);
    assert(parsed.misc.kernelsnitch_collisions.value_or(0) == 4);
    assert(parsed.misc.mm_struct_sz.value_or(0) == 0x400);
    assert(parsed.execution.w1_attempts == 15);
    assert(parsed.execution.race_route_done_timeout_ms == 300000);
    assert(parsed.execution.handoff_enforce_poll_interval_ms == 100);
    assert(parsed.geometry.mcast_waiter_off.value_or(-1) == 96);
    assert(parsed.geometry.mcast_buffer_size.value_or(0) == 512);

    /* ---- Strict values and presence. ---- */
    {
        profile::kernel_offsets strict = {};
        strict.uname_r = "strict";
        strict.route = ghostlock::profile::kRouteSelectStack;
        /* A provided 0 is preserved and present (not "unset"). */
        strict.geometry.pselect_waiter_shift = 0;
        strict.misc.kernel_phys_load = 0;
        strict.misc.mm_struct_sz = 0;
        assert(round_trip(strict, &parsed, release, sizeof(release)) == 0);
        assert(parsed.geometry.pselect_waiter_shift.has_value() &&
               *parsed.geometry.pselect_waiter_shift == 0);
        assert(parsed.misc.kernel_phys_load.has_value() &&
               *parsed.misc.kernel_phys_load == 0);
        assert(parsed.misc.mm_struct_sz.has_value() && *parsed.misc.mm_struct_sz == 0);

        /* The same for the multicast route's own section. */
        profile::kernel_offsets mstrict = {};
        mstrict.uname_r = "mstrict";
        mstrict.route = ghostlock::profile::kRouteMulticastWaiter;
        mstrict.geometry.mcast_waiter_off = 0;
        assert(round_trip(mstrict, &parsed, release, sizeof(release)) == 0);
        assert(parsed.geometry.mcast_waiter_off.has_value() &&
               *parsed.geometry.mcast_waiter_off == 0);

        /* Negatives round-trip exactly. */
        profile::kernel_offsets neg = {};
        neg.uname_r = "neg";
        neg.route = ghostlock::profile::kRouteSelectStack;
        neg.geometry.pselect_waiter_shift = -2;
        assert(round_trip(neg, &parsed, release, sizeof(release)) == 0);
        assert(parsed.geometry.pselect_waiter_shift.value_or(99) == -2);

        /* The lock anchor round-trips, and an absent one stays absent (that
         * absence is what keeps the pre-anchor reclaimed-page behaviour). */
        profile::kernel_offsets anchored = {};
        anchored.uname_r = "anchored";
        anchored.route = ghostlock::profile::kRouteSelectStack;
        anchored.geometry.select_lock_anchor_image = 0x2a3a590;
        /* The grid travels with the offset: a bound that ships separately from
         * the region it bounds is what lets a profile walk past it. */
        anchored.geometry.select_lock_anchor_bytes = 0x1000;
        anchored.geometry.select_lock_anchor_stride = 0x20;
        assert(round_trip(anchored, &parsed, release, sizeof(release)) == 0);
        assert(parsed.geometry.select_lock_anchor_image.value_or(0) == 0x2a3a590);
        assert(parsed.geometry.select_lock_anchor_bytes.value_or(0) == 0x1000);
        assert(parsed.geometry.select_lock_anchor_stride.value_or(0) == 0x20);

        profile::kernel_offsets unanchored = {};
        unanchored.uname_r = "unanchored";
        unanchored.route = ghostlock::profile::kRouteSelectStack;
        unanchored.geometry.pselect_waiter_shift = -2;
        assert(round_trip(unanchored, &parsed, release, sizeof(release)) == 0);
        assert(!parsed.geometry.select_lock_anchor_image.has_value());
        assert(!parsed.geometry.select_lock_anchor_bytes.has_value());
        assert(!parsed.geometry.select_lock_anchor_stride.has_value());

        /* An absent optional stays absent after the round trip. */
        profile::kernel_offsets absent = {};
        absent.uname_r = "absent";
        absent.route = ghostlock::profile::kRouteMulticastWaiter;
        absent.geometry.mcast_buffer_size = 264;
        assert(round_trip(absent, &parsed, release, sizeof(release)) == 0);
        assert(!parsed.geometry.mcast_waiter_off.has_value());
        assert(!parsed.misc.mm_struct_sz.has_value());
        assert(parsed.geometry.mcast_buffer_size.value_or(0) == 264);
    }

    /* ---- Header bytes: magic, version 2, middleware id, release. ---- */
    {
        char buffer[8192];
        values.route = ghostlock::profile::kRouteSelectStack;
        const int32_t size = binary_profile::serialize(&values, buffer, sizeof(buffer));
        assert(size > 0);
        const auto *bytes = reinterpret_cast<const unsigned char *>(buffer);
        const uint32_t magic = static_cast<uint32_t>(bytes[0]) |
                               (static_cast<uint32_t>(bytes[1]) << 8) |
                               (static_cast<uint32_t>(bytes[2]) << 16) |
                               (static_cast<uint32_t>(bytes[3]) << 24);
        const uint16_t version = static_cast<uint16_t>(bytes[4] | (bytes[5] << 8));
        const uint16_t middleware = static_cast<uint16_t>(bytes[10] | (bytes[11] << 8));
        assert(magic == 0x0D000721u && binary_profile::kMagic == 0x0D000721u);
        assert(version == 2u && binary_profile::kVersion == 2u);
        assert(middleware == ghostlock::profile::kRouteSelectStack);
        assert(bytes[16] == '6'); /* release starts right after the 16-byte header */
    }

    /* ---- White box: section/entry decoding. ---- */
    {
        /* Unknown section is skipped; unknown key is ignored; known keys apply. */
        std::string doc = build_doc(
            ghostlock::profile::kRouteTcpZerocopy, "unknown",
            {
                {"not_a_section", {{"x", 1}}},
                {"route.tcp_zerocopy", {{"not_a_field", 123}, {"attempts", 2000}}},
            });
        assert(parse_doc(doc, &parsed, release, sizeof(release)) == 0);
        assert(parsed.execution.tcp_attempts == 2000);

        /* A key of another section is ignored. */
        doc = build_doc(ghostlock::profile::kRouteTcpZerocopy, "other",
                        {{"route.select_stack", {{"waiter_shift", 9}}}});
        assert(parse_doc(doc, &parsed, release, sizeof(release)) == 0);
        assert(!parsed.geometry.pselect_waiter_shift.has_value());

        /* Duplicated key applies last-wins. */
        doc = build_doc(ghostlock::profile::kRouteTcpZerocopy, "dup",
                        {{"route.tcp_zerocopy", {{"attempts", 1}, {"attempts", 2}}}});
        assert(parse_doc(doc, &parsed, release, sizeof(release)) == 0);
        assert(parsed.execution.tcp_attempts == 2);

        /* Signed values sign-extend exactly. */
        doc = build_doc(ghostlock::profile::kRouteSelectStack, "signed",
                        {{"route.select_stack", {{"waiter_shift", -2}}}});
        assert(parse_doc(doc, &parsed, release, sizeof(release)) == 0);
        assert(parsed.geometry.pselect_waiter_shift.value_or(0) == -2);

        /* The select route's optional lock anchor is decoded by wire name. */
        doc = build_doc(ghostlock::profile::kRouteSelectStack, "anchor",
                        {{"route.select_stack", {{"lock_anchor_image", 0x2a3a590}}}});
        assert(parse_doc(doc, &parsed, release, sizeof(release)) == 0);
        assert(parsed.geometry.select_lock_anchor_image.value_or(0) == 0x2a3a590);
        /* The geometry keys are decoded by name too, and stay absent when the
         * document omits them (native then uses this build's 0x1000 / 0x20). */
        assert(!parsed.geometry.select_lock_anchor_bytes.has_value());
        assert(!parsed.geometry.select_lock_anchor_stride.has_value());

        doc = build_doc(ghostlock::profile::kRouteSelectStack, "anchor-geom",
                        {{"route.select_stack",
                          {{"lock_anchor_image", 0x2a3a590},
                           {"lock_anchor_bytes", 0x1000},
                           {"lock_anchor_stride", 0x20}}}});
        assert(parse_doc(doc, &parsed, release, sizeof(release)) == 0);
        assert(parsed.geometry.select_lock_anchor_bytes.value_or(0) == 0x1000);
        assert(parsed.geometry.select_lock_anchor_stride.value_or(0) == 0x20);

        /* An empty document body is valid (everything stays default/absent). */
        doc = build_doc(ghostlock::profile::kRouteMulticastWaiter, "empty", {});
        assert(parse_doc(doc, &parsed, release, sizeof(release)) == 0);
        assert(!parsed.geometry.mcast_waiter_off.has_value());
    }

    /* ---- White box: truncations and lying counts. ---- */
    {
        std::string doc = build_doc(ghostlock::profile::kRouteTcpZerocopy, "trunc",
                                    {{"route.tcp_zerocopy", {{"attempts", 5}}}});
        const size_t entries_at = doc.size() - (1 + std::strlen("attempts") + 8);
        assert(parse_doc(doc.substr(0, entries_at - 1), &parsed, release, sizeof(release)) == -1);
        assert(parse_doc(doc.substr(0, entries_at + 1), &parsed, release, sizeof(release)) == -1);
        assert(parse_doc(doc.substr(0, doc.size() - 3), &parsed, release,
                         sizeof(release)) == -1);

        /* Header claiming more entries than present. */
        std::string lying = doc;
        lying[entries_at - 4] = 3;
        assert(parse_doc(lying, &parsed, release, sizeof(release)) == -1);
    }

    /* ---- Rejections: magic, version, ids, routes, short buffers. ---- */
    {
        char buffer[8192];
        values.route = ghostlock::profile::kRouteSelectStack;
        const int32_t size = binary_profile::serialize(&values, buffer, sizeof(buffer));
        assert(size > 0);
        char broken[8192];
        memcpy(broken, buffer, static_cast<size_t>(size));
        broken[0] = 'X';
        assert(binary_profile::parse(std::string_view(broken, static_cast<size_t>(size)), &parsed,
                                     release, sizeof(release)) == -1);
        assert(binary_profile::parse(std::string_view(buffer, static_cast<size_t>(size) - 1),
                                     &parsed, release, sizeof(release)) == -1);
        char tiny_release[4] = {0};
        assert(binary_profile::parse(std::string_view(buffer, static_cast<size_t>(size)), &parsed,
                                     tiny_release, sizeof(tiny_release)) == -1);

        for (int version : {1, 3, 4, 5}) {
            std::string doc = build_doc(ghostlock::profile::kRouteSelectStack, "v", {});
            doc[4] = static_cast<char>(version & 0xff);
            doc[5] = static_cast<char>(version >> 8);
            assert(parse_doc(doc, &parsed, release, sizeof(release)) == -1);
        }
        for (int route : {0, 4, 99}) {
            const std::string doc = build_doc(static_cast<uint8_t>(route), "r", {});
            assert(parse_doc(doc, &parsed, release, sizeof(release)) == -1);
        }
        assert(parse_doc(build_doc(ghostlock::profile::kRouteSelectStack, "f", {}, 9,
                                   binary_profile::kBackendCve202643499),
                         &parsed, release, sizeof(release)) == -1);
        assert(parse_doc(build_doc(ghostlock::profile::kRouteSelectStack, "b",
                                   {}, binary_profile::kFrontendRootChild, 9),
                         &parsed, release, sizeof(release)) == -1);

        /* Component ids decode and are reported. */
        profile::kernel_offsets ids_values = {};
        ids_values.uname_r = "component-ids";
        ids_values.route = ghostlock::profile::kRouteSelectStack;
        char idbuf[8192];
        const int32_t idsize = binary_profile::serialize(&ids_values, idbuf, sizeof(idbuf));
        assert(idsize > 0);
        binary_profile::component_ids ids{};
        assert(binary_profile::parse(std::string_view(idbuf, static_cast<size_t>(idsize)), &parsed,
                                     release, sizeof(release), &ids) == 0);
        assert(ids.frontend == binary_profile::kFrontendRootChild);
        assert(ids.backend == binary_profile::kBackendCve202643499);
        assert(ids.middleware == ghostlock::profile::kRouteSelectStack);

        /* A profile without a declared route never serializes. */
        values.route = ghostlock::profile::kRouteAuto;
        assert(binary_profile::serialize(&values, buffer, sizeof(buffer)) == -1);
    }

    /* ---- Schema digest: round trip, tampering, and the cross-language vector.
     *
     * The digest covers the *schema* (every key both sides declare, present or
     * not), so the Kotlin implementation in `NativeProfile.kt` and this one
     * must produce the same number for the same document. The vector below is
     * asserted identically in `NativeProfileDigestTest.kt`: it is the
     * cross-language contract between the two implementations. ---- */
    {
        char buffer[8192];
        profile::kernel_offsets golden = {};
        golden.uname_r = "digest-vector";
        golden.route = ghostlock::profile::kRouteSelectStack;
        golden.meta.kernel_major = 5;
        golden.misc.compact_waiter = 1;
        golden.geometry.pselect_waiter_shift = -2;
        golden.geometry.select_lock_anchor_image = 0x2a3a590;
        golden.geometry.select_lock_anchor_bytes = 0x1000;
        golden.geometry.select_lock_anchor_stride = 0x20;
        golden.execution.select_enter_delay_us = 5000;
        golden.execution.select_timeout_us = 30000;
        const int32_t size = binary_profile::serialize(&golden, buffer, sizeof(buffer));
        assert(size > 0);
        binary_profile::digests digests{};
        assert(binary_profile::parse(std::string_view(buffer, static_cast<size_t>(size)),
                                     &parsed, release, sizeof(release), nullptr, &digests) == 0);
        assert(digests.transmitted.has_value());
        assert(digests.transmitted.value() == digests.computed);
        assert(digests.transmitted.value() == kGoldenSchemaDigest);

        /* Serializing twice is byte-identical: the digest is a function of the
         * document, not of the run. */
        char again[8192];
        const int32_t again_size = binary_profile::serialize(&golden, again, sizeof(again));
        assert(again_size == size);
        assert(memcmp(again, buffer, static_cast<size_t>(size)) == 0);

        /* A document from an app build that predates the digest parses, and
         * says so — nothing can be verified. */
        std::string legacy = build_doc(ghostlock::profile::kRouteSelectStack, "legacy",
                                       {{"route.select_stack", {{"waiter_shift", -2}}}});
        binary_profile::digests legacy_digests{};
        assert(binary_profile::parse(std::string_view(legacy), &parsed, release, sizeof(release),
                                     nullptr, &legacy_digests) == 0);
        assert(!legacy_digests.transmitted.has_value());
        assert(legacy_digests.computed != 0);

        std::string document(buffer, static_cast<size_t>(size));

        /* One value byte changed in transit. */
        const size_t anchor_key = document.find("lock_anchor_image");
        assert(anchor_key != std::string::npos);
        std::string tampered = document;
        tampered[anchor_key + std::strlen("lock_anchor_image")] ^= 0x01;
        assert(parse_doc(tampered, &parsed, release, sizeof(release)) ==
               binary_profile::kDigestMismatch);

        /* A key the sender declared and this build does not decode — the way a
         * new profile key once vanished between the document and the wire. It
         * is present in the document, so the sender's schema counted it; this
         * decode does not, and the streams diverge. */
        std::string renamed = document;
        renamed[anchor_key + std::strlen("lock_anchor_image") - 1] = 'X';
        assert(parse_doc(renamed, &parsed, release, sizeof(release)) ==
               binary_profile::kDigestMismatch);

        /* A wrong digest, and a digest that is truncated away mid-entry. */
        assert(parse_doc(build_doc(ghostlock::profile::kRouteSelectStack, "wrong",
                                   {{"meta", {{"kernel_major", 5}}},
                                    {"profile", {{"digest", 0x1234}}}},
                                   binary_profile::kFrontendRootChild,
                                   binary_profile::kBackendCve202643499),
                         &parsed, release, sizeof(release)) ==
               binary_profile::kDigestMismatch);
        assert(parse_doc(document.substr(0, document.size() - 4), &parsed, release,
                         sizeof(release)) == -1);

        /* patches made after the digest was computed stay valid: safe_mode is
         * excluded from the stream because the app rewrites it in transit. */
        std::string safe = document;
        const size_t safe_key = safe.find("safe_mode");
        assert(safe_key != std::string::npos);
        safe[safe_key + std::strlen("safe_mode")] = 1;
        assert(parse_doc(safe, &parsed, release, sizeof(release)) == 0);
        assert(parsed.meta.safe_mode == 1);
    }

    puts("profile_binary_test: ok");
    return 0;
}
