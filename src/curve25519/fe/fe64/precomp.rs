// TODO to compute -- all initialized to ONE

use super::super::super::ge::GePrecomp;
use super::Fe;

#[rustfmt::skip]
pub(crate) const BI: [GePrecomp; 8] = [
    GePrecomp {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ONE,
    },
    GePrecomp {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ONE,
    },
    GePrecomp {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ONE,
    },
    GePrecomp {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ONE,
    },
    GePrecomp {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ONE,
    },
    GePrecomp {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ONE,
    },
    GePrecomp {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ONE,
    },
    GePrecomp {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ONE,
    },
];

#[rustfmt::skip]
pub(crate) const GE_BASE: [[GePrecomp; 8]; 32] = [
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
    [
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
        GePrecomp {
            y_plus_x: Fe::ONE,
            y_minus_x: Fe::ONE,
            xy2d: Fe::ONE,
        },
    ],
];
