pub struct Pr;

pub struct NoPr;

pub trait PredictionResistance {
    const IS_PR: bool;
}

impl PredictionResistance for Pr {
    const IS_PR: bool = true;
}

impl PredictionResistance for NoPr {
    const IS_PR: bool = false;
}
