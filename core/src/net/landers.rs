//! The production landers, each reachable on Tor and, all but the primary for now, on Anyone.

use super::pool::Lander;

/// The production landers in their standby order, each given 20 seconds. The primary was confirmed by
/// a transfer that settled through it, and its Anyone address comes when its machine is back.
pub(super) const LANDERS: [Lander; 5] = [
    Lander { tor: "mforujillfk4w5h2zqgxdzendn3qb2zes4r2h57ownojshhmtcdzgdyd.onion", anyone: None },
    Lander {
        tor: "lfpw5uoslfiqmwsc7o2d2qts3grmfnixrhae3hkgkv6x4dlxpvafp4yd.onion",
        anyone: Some("iywfqrj6xyqey574vjtljswxhzeoeqfvlmpqfueva4stooiu3blo7sqd.anyone"),
    },
    Lander {
        tor: "7ywwruseitmycfjwh2upbecetm6edej7pkxpp4xtzmtioes4ubs63kad.onion",
        anyone: Some("5swdytwdtcspbntuofrknlqa7ls2nw2zol2o6tts2jv5hs67n4ee5nad.anyone"),
    },
    Lander {
        tor: "g7uyxmffgim7sneprrkdp4ecshupvd3kuaadho6f7e2gcd3gazimriyd.onion",
        anyone: Some("ywhgp672zlndlpjubaq23yhbuy526335jfgl2zr74emhgoepovh56lid.anyone"),
    },
    Lander {
        tor: "ewjq3ue43pclh6qyx3triup7org64nykbjgy7tmderlzzx27kstfdiqd.onion",
        anyone: Some("wusdfhdpumeamiyex3v625zled37m2lw24x4bxr3mngu75ryz7vurvad.anyone"),
    },
];
