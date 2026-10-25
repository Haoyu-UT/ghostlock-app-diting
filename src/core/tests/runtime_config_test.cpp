/* Host fixed-vector test for the vr.ko tri-state parser. The UI's On/Off is
 * final; only an explicit value leaves Auto, and the old boolean spellings stay
 * understandable so an unreleased build's environment cannot flip a default. */

#include "../session/runtime_config.h"

#include <cassert>
#include <cstdio>

#include <string>

using namespace ghostlock;

int32_t main(void) {
    using config::VrKoMode;

    assert(config::parse_vr_ko_mode(nullptr) == VrKoMode::Auto);
    assert(config::parse_vr_ko_mode("") == VrKoMode::Auto);
    assert(config::parse_vr_ko_mode("auto") == VrKoMode::Auto);
    assert(config::parse_vr_ko_mode("garbage") == VrKoMode::Auto);

    assert(config::parse_vr_ko_mode("on") == VrKoMode::On);
    assert(config::parse_vr_ko_mode("1") == VrKoMode::On);
    assert(config::parse_vr_ko_mode("true") == VrKoMode::On);

    assert(config::parse_vr_ko_mode("off") == VrKoMode::Off);
    assert(config::parse_vr_ko_mode("0") == VrKoMode::Off);
    assert(config::parse_vr_ko_mode("false") == VrKoMode::Off);

    assert(std::string(config::vr_ko_mode_name(VrKoMode::Auto)) == "auto");
    assert(std::string(config::vr_ko_mode_name(VrKoMode::On)) == "on");
    assert(std::string(config::vr_ko_mode_name(VrKoMode::Off)) == "off");

    puts("runtime_config_test: ok");
    return 0;
}
