pub struct Pr;

pub struct NoPr;

pub trait PredictionResistance {
    fn is_pr() -> bool;
}

impl PredictionResistance for Pr {
    fn is_pr() -> bool {
        true
    }
}

impl PredictionResistance for NoPr {
    fn is_pr() -> bool {
        false
    }
}
