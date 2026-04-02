mod aot;

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_read_from_file() {
        let bytes = read_from_file("tests/xdp_hello.o").expect("Failed to read from file");
        assert!(bytes.len() == 72, "Unexpected byte length: {}", bytes.len());
    }
}