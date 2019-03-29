pub trait ShannonEntropy {
    fn shannon_entropy(&self) -> f64;
}
impl ShannonEntropy for [u8] {
    fn shannon_entropy(&self) -> f64 {
        // Initialize a dataset of byte frequencies
        let mut frequencies: [usize; 256] = [0; 256];
        // Get byte frequencies
        for byte in self {
            frequencies[*byte as usize] += 1;
        }
        // Iterate over frequencies
        frequencies
            .into_iter()
            .map(|frequency| {
                // Handle 0 values
                if *frequency == 0 {
                    0.0
                } else {
                    // Normalize the frequency
                    let frequency: f64 = (*frequency as f64) / (self.len() as f64);
                    // Individual entropy value
                    frequency * frequency.log2()
                }
            })
            .sum::<f64>()
            .abs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter;
    /// Tests the shannon entropy function
    #[test]
    fn test_shannon_entropy() {
        // Empty slice
        assert_eq!([].shannon_entropy(), 0.0);
        // Single value
        assert_eq!([0].shannon_entropy(), 0.0);
        assert_eq!([1].shannon_entropy(), 0.0);
        // Many single values
        for exponent in 1..10 {
            // Build a slice
            let data: Vec<u8> = iter::repeat(1).take(2_usize.pow(exponent)).collect();
            // Evaluate entropy
            assert_eq!(data.shannon_entropy(), 0.0);
        }
        // Uniform distribution
        for exponent in 1..8 {
            // Build a slice
            let data: Vec<u8> = (0..2_u8.pow(exponent)).collect();
            // Evaluate entropy
            assert_eq!(data.shannon_entropy(), exponent as f64);
        }
        // TODO: more distribution tests
    }
}
