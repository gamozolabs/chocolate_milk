#![no_std]

use core::arch::x86_64::*;

/// Structure which gives access to a `hash` member function, allowing 128-bit
/// non-cryptographic-hashing of a slice of bytes
/// 
/// This structure exists only to protect access to the `hash` function by first
/// validating that the current CPU has AES-NI instructions available for use.
/// This check is done when `FalkHasher::new()` is used to create a new hasher
/// and never again. This makes `FalkHasher::hash()` have no feature detection
/// overhead while still guarding use of falkhash with a runtime CPU feature
/// check.
pub struct FalkHasher(());

impl FalkHasher {
    /// Create a new `FalkHasher`
    pub fn new() -> Self {
        let features = cpu::get_cpu_features();
        assert!(features.aesni, "AES-NI required for falkhash");

        // If AES is present it's safe to return an object which allows
        // use of `falkhash` from this point on
        FalkHasher(())
    }

    /// A non-cryptographically-safe hash leveraging AES instructions on x86 to
    /// quickly generate a 128-bit hash the input `buffer`
    pub fn hash(&self, buffer: &[u8]) -> u128 {
        unsafe { crate::falkhash_int(buffer) }
    }
}

/// A non-cryptographically-safe hash leveraging AES instructions on x86 to
/// quickly generate a 128-bit hash the input `buffer`
#[target_feature(enable = "aes")]
unsafe fn falkhash_int(buffer: &[u8]) -> u128 {
    // Seed is initialized with random values, and also takes into account the
    // buffer length
    let seed =
        _mm_set_epi64x(0x2a4ba81ac0bfd4fe + buffer.len() as i64,
                       0x52c8611d3941be6a);

    // Hash starts out as the seed value
    let mut hash = seed;

    // Scratch buffer used to pad out buffers to 0x50 bytes if they are not
    // evenly divisble by 0x50
    let mut tmp = [0u8; 0x50];
    
    // Go through each 0x50 byte chunk
    for chunk in buffer.chunks(0x50) {
        // Check if this chunk is large enough for our operation size
        let ptr = if chunk.len() < 0x50 {
            // Pad with zeros by copying to the temporary buffer
            tmp[..chunk.len()].copy_from_slice(chunk);
            &tmp[..]
        } else {
            // Chunk was exactly 0x50 bytes, leave it as is
            chunk
        };

        // Load up all the raw data
        let p0 = _mm_loadu_si128((ptr.as_ptr() as *const __m128i).offset(0));
        let p1 = _mm_loadu_si128((ptr.as_ptr() as *const __m128i).offset(1));
        let p2 = _mm_loadu_si128((ptr.as_ptr() as *const __m128i).offset(2));
        let p3 = _mm_loadu_si128((ptr.as_ptr() as *const __m128i).offset(3));
        let p4 = _mm_loadu_si128((ptr.as_ptr() as *const __m128i).offset(4));

        // Xor against `seed`
        let p0 = _mm_xor_si128(p0, seed);
        let p1 = _mm_xor_si128(p1, seed);
        let p2 = _mm_xor_si128(p2, seed);
        let p3 = _mm_xor_si128(p3, seed);
        let p4 = _mm_xor_si128(p4, seed);

        // `aesenc` to merge into `p0`
        let p0 = _mm_aesenc_si128(p0, p1);
        let p0 = _mm_aesenc_si128(p0, p2);
        let p0 = _mm_aesenc_si128(p0, p3);
        let p0 = _mm_aesenc_si128(p0, p4);

        // Finalize by `aesenc`ing against `seed`
        let p0 = _mm_aesenc_si128(p0, seed);

        // Merge this block into the hash
        hash = _mm_aesenc_si128(hash, p0);
    }

    // Finalize hash by `aesenc`ing against the seed four times
    hash = _mm_aesenc_si128(hash, seed);
    hash = _mm_aesenc_si128(hash, seed);
    hash = _mm_aesenc_si128(hash, seed);
    hash = _mm_aesenc_si128(hash, seed);

    // Return out the hash!
    *((&hash as *const __m128i) as *const u128)
}

#[test]
fn validate_correctness() {
    // Hash a buffer full of 'A's at different sizes and make sure we get the
    // expected results for the hash.
    // We try a bunch of different sizes to make sure we're correctly handling
    // padding of data when it's less than the internal hash chunk size.

    // Create a new `FalkHasher`
    let fh = FalkHasher::new();

    // Buffer of 'A's
    let test_data = [0x41u8; 128];

    assert!(fh.hash(&test_data[..0x00]) == 0x4208942bcc22d29ce42a0c56daaf5088);
    assert!(fh.hash(&test_data[..0x01]) == 0x489903837004cd2617a44fae84df6e64);
    assert!(fh.hash(&test_data[..0x02]) == 0x3db8c8b575d65c8017411771965c667b);
    assert!(fh.hash(&test_data[..0x03]) == 0x8bcadd96fe92478b756752736b2afc5e);
    assert!(fh.hash(&test_data[..0x04]) == 0x77d97e0e05ca147689729bd9cb3d25f9);
    assert!(fh.hash(&test_data[..0x05]) == 0xd673c188d4ea71f106416a3a6476abc1);
    assert!(fh.hash(&test_data[..0x06]) == 0xce9cb1472235b776e6b16a340cd4a36d);
    assert!(fh.hash(&test_data[..0x07]) == 0x8d68a27f5c2c26710b080eacdb96f3a4);
    assert!(fh.hash(&test_data[..0x08]) == 0x6d53b4eb5ea247bf0dfd453ad8ad5e6f);
    assert!(fh.hash(&test_data[..0x09]) == 0xc36870d8bae6d870c840df4cb4e13b05);
    assert!(fh.hash(&test_data[..0x0a]) == 0x556ad9cd2c556ebe31613046b1668bfa);
    assert!(fh.hash(&test_data[..0x0b]) == 0x528fbdd299fcd286e579afb2b588dedc);
    assert!(fh.hash(&test_data[..0x0c]) == 0x50e9dc0cc0d37464984dddc3fea801e7);
    assert!(fh.hash(&test_data[..0x0d]) == 0xd2a878fc3ba87a573f76d27bbccddfe3);
    assert!(fh.hash(&test_data[..0x0e]) == 0xb4cb18caf0ede9b822b140b5b5108c0f);
    assert!(fh.hash(&test_data[..0x0f]) == 0x38a6eee841f4cc496a6df40300835d90);
    assert!(fh.hash(&test_data[..0x10]) == 0xb11e14830381b1f77c421d6388f005d2);
    assert!(fh.hash(&test_data[..0x11]) == 0xfcf434743799df67707e7d028359ffea);
    assert!(fh.hash(&test_data[..0x12]) == 0x56413713a7fbd1822c4a4086bc30bc0f);
    assert!(fh.hash(&test_data[..0x13]) == 0x5b43f47f1694fcbe4dab2723923dcd25);
    assert!(fh.hash(&test_data[..0x14]) == 0xf8820c5bf51e39df6b0fe680317bed50);
    assert!(fh.hash(&test_data[..0x15]) == 0x6c568012d2c3ffac7725727b4e6abbdc);
    assert!(fh.hash(&test_data[..0x16]) == 0x9e14134e254e93a2de37a54b80cb5d0d);
    assert!(fh.hash(&test_data[..0x17]) == 0xc25baa45a8477a8e4f356d4141d47a68);
    assert!(fh.hash(&test_data[..0x18]) == 0x9492255bb3f0b26b6dde29c1caab41c8);
    assert!(fh.hash(&test_data[..0x19]) == 0xf6d214cb9a86ed2d4426a77f591cfbce);
    assert!(fh.hash(&test_data[..0x1a]) == 0x3f8943ab20c6809887b45c0f3dfc3118);
    assert!(fh.hash(&test_data[..0x1b]) == 0xadc0a2c1c2b556403678c37c190f7a77);
    assert!(fh.hash(&test_data[..0x1c]) == 0x6d79539f0eeae4d1bd99b3c688f321d8);
    assert!(fh.hash(&test_data[..0x1d]) == 0xdb180909e29b37acd858055aa71b0d37);
    assert!(fh.hash(&test_data[..0x1e]) == 0xc2d21f2fc4bf4cabd0d5c433229ae657);
    assert!(fh.hash(&test_data[..0x1f]) == 0x695e7481c2db7defb13d7933a7d335ee);
    assert!(fh.hash(&test_data[..0x20]) == 0x96bb8bb54a0212f71b5a6be72addc913);
    assert!(fh.hash(&test_data[..0x21]) == 0x4ec919773abf7660acf3f8d078a702ac);
    assert!(fh.hash(&test_data[..0x22]) == 0x107a9d7af19b3d9c2d8a44dcac947302);
    assert!(fh.hash(&test_data[..0x23]) == 0x6db6313c39dbdce322b46b9de6140431);
    assert!(fh.hash(&test_data[..0x24]) == 0x7289c5dba45a814d6bd85ee0b2673f89);
    assert!(fh.hash(&test_data[..0x25]) == 0x2a4a4790b528df5652671071af084610);
    assert!(fh.hash(&test_data[..0x26]) == 0x0b58ffcab3292ac18e387adc0e429d06);
    assert!(fh.hash(&test_data[..0x27]) == 0xeb370058e83b603e158df11921ee7f25);
    assert!(fh.hash(&test_data[..0x28]) == 0x2b3106e63b234bb4aa3671a32ea28068);
    assert!(fh.hash(&test_data[..0x29]) == 0x3899e92051e82c0d53816a1bf84fa9bd);
    assert!(fh.hash(&test_data[..0x2a]) == 0x9f05cadfe76b2de64723c5d0284b055e);
    assert!(fh.hash(&test_data[..0x2b]) == 0xeb99a42e69fc8211d123f3a7699619bd);
    assert!(fh.hash(&test_data[..0x2c]) == 0x94f4d167b239faedef84b52072ad5ee7);
    assert!(fh.hash(&test_data[..0x2d]) == 0x9bad00b29b997f0962acd56ebeb91302);
    assert!(fh.hash(&test_data[..0x2e]) == 0x24c260c9a415b890af0f0d5ba274e07e);
    assert!(fh.hash(&test_data[..0x2f]) == 0xcad210a611ecce1991a7971f2410fb1f);
    assert!(fh.hash(&test_data[..0x30]) == 0x20925b42385d71a0994649534b7572ee);
    assert!(fh.hash(&test_data[..0x31]) == 0x87a4d86880c7a8ced1c4a4e185a508a9);
    assert!(fh.hash(&test_data[..0x32]) == 0xb06bef3d05681aa41fb1fccac2f5ff17);
    assert!(fh.hash(&test_data[..0x33]) == 0x51587eb5a4ae727a2c10082154ce487d);
    assert!(fh.hash(&test_data[..0x34]) == 0x8605c3378154a19ed166ccbc518ce950);
    assert!(fh.hash(&test_data[..0x35]) == 0x71e100167a049854685577695ecc3966);
    assert!(fh.hash(&test_data[..0x36]) == 0x0f84c5ae68063821376ac9c84e916dd1);
    assert!(fh.hash(&test_data[..0x37]) == 0x0577e3325e69ae592222b41f654b4f39);
    assert!(fh.hash(&test_data[..0x38]) == 0xe79943d1088e52eec253f616f9517f1b);
    assert!(fh.hash(&test_data[..0x39]) == 0x116bba02b2717caf756de21739ca436f);
    assert!(fh.hash(&test_data[..0x3a]) == 0xcb8da9b5cd74f35fcd3f9593eb5ed601);
    assert!(fh.hash(&test_data[..0x3b]) == 0x18e25a2269dbd3c49fb84acd55503f78);
    assert!(fh.hash(&test_data[..0x3c]) == 0x79f1f6c070662b9be4a02b18dfb9fd13);
    assert!(fh.hash(&test_data[..0x3d]) == 0xe070c8c0158ce4d8278a68899f6a82e5);
    assert!(fh.hash(&test_data[..0x3e]) == 0x6bc91aee6308bd3318e1d14d7a3d49d5);
    assert!(fh.hash(&test_data[..0x3f]) == 0x3bc6da3ca213b637b0c630302d4c96a9);
    assert!(fh.hash(&test_data[..0x40]) == 0xb8363ca2747026cbbc38aee9babf115e);
    assert!(fh.hash(&test_data[..0x41]) == 0xf15e6ca7d3f39bb42bfb174cd47601d2);
    assert!(fh.hash(&test_data[..0x42]) == 0x8ff97a04055abf60fc158974dae33e3a);
    assert!(fh.hash(&test_data[..0x43]) == 0xcbe80bb1894aa411465ef3d5b09aa9cf);
    assert!(fh.hash(&test_data[..0x44]) == 0x1826f61a6773d90c1d684439a85cde7f);
    assert!(fh.hash(&test_data[..0x45]) == 0x9088c619dc6c4993e464c5854eb00fef);
    assert!(fh.hash(&test_data[..0x46]) == 0xdabe91cf7b80c2b5fb7d32f81d90060f);
    assert!(fh.hash(&test_data[..0x47]) == 0x1673f80d93d65fb1def14e095580a4f3);
    assert!(fh.hash(&test_data[..0x48]) == 0x23983232158b8999256972203df8020c);
    assert!(fh.hash(&test_data[..0x49]) == 0x0a3c8c6c4b066bb9faaca704c61b6e32);
    assert!(fh.hash(&test_data[..0x4a]) == 0x003209cbf8ea9a4085656adfe215265b);
    assert!(fh.hash(&test_data[..0x4b]) == 0xb887392707af86556b1097a1b89d3e0d);
    assert!(fh.hash(&test_data[..0x4c]) == 0xb67ef5d61cb027f2a132df75b0ef9f4e);
    assert!(fh.hash(&test_data[..0x4d]) == 0x595951ec2bf4cbf05b8a0382b0fa5921);
    assert!(fh.hash(&test_data[..0x4e]) == 0x3e98b49ddaa6327a8064205acd7ed114);
    assert!(fh.hash(&test_data[..0x4f]) == 0x33fd8878d2de0fe10119e0e9ed813a73);
    assert!(fh.hash(&test_data[..0x50]) == 0x28310c491c3605f71922f1cb4a827ce9);
    assert!(fh.hash(&test_data[..0x51]) == 0xbe83f0b1a23c22fd1c3709513671711e);
    assert!(fh.hash(&test_data[..0x52]) == 0xf58579eceae78f038dde8369372e2973);
    assert!(fh.hash(&test_data[..0x53]) == 0xf3b47b70eaf05f0fecb11058a9d9d2b9);
    assert!(fh.hash(&test_data[..0x54]) == 0x28baa7bc1b1eb62d75a5bd3bea5390c7);
    assert!(fh.hash(&test_data[..0x55]) == 0xa4f3f3c8f043cc4e7a7e00f39c31dad6);
    assert!(fh.hash(&test_data[..0x56]) == 0x9944d09410d705234031c26862125426);
    assert!(fh.hash(&test_data[..0x57]) == 0x3a689420ceaf9fa42f5209784d1bd508);
    assert!(fh.hash(&test_data[..0x58]) == 0x73d20fa06762a542eaf25020db35c2f1);
    assert!(fh.hash(&test_data[..0x59]) == 0xe7304fcf1ecc199f11d376e5abf11724);
    assert!(fh.hash(&test_data[..0x5a]) == 0x31fb056271e1c3ffde8a60aeb10ac9f0);
    assert!(fh.hash(&test_data[..0x5b]) == 0x4595eda877b512f16759c15ca1c6d6c6);
    assert!(fh.hash(&test_data[..0x5c]) == 0x11ea5290120c784f513cb09753c9eff8);
    assert!(fh.hash(&test_data[..0x5d]) == 0x9137260e034d3f20f46ccf8c95920c3e);
    assert!(fh.hash(&test_data[..0x5e]) == 0xd1caeabee2b2184427a496f3d617a929);
    assert!(fh.hash(&test_data[..0x5f]) == 0x2c37a3d8c37e7cf46614748fde2740f6);
    assert!(fh.hash(&test_data[..0x60]) == 0x5ca6be3c15723fcdc126da32a900e756);
    assert!(fh.hash(&test_data[..0x61]) == 0x5ee6ea3d25ad6b63f19eba491fdf5fd0);
    assert!(fh.hash(&test_data[..0x62]) == 0x86d1f5893a3762e1be161f4abd4860bd);
    assert!(fh.hash(&test_data[..0x63]) == 0x106f9d93575fe2ae4e9e4a980209a1d2);
    assert!(fh.hash(&test_data[..0x64]) == 0x2ac25f909974c21e02ffc38bdb67f8c5);
    assert!(fh.hash(&test_data[..0x65]) == 0x1b8d8ee55850f59b2760f79c04ac41bb);
    assert!(fh.hash(&test_data[..0x66]) == 0xaf517df53c73cc63541d059349428c85);
    assert!(fh.hash(&test_data[..0x67]) == 0x15c90f5346e9c0c10e18b6948cff7def);
    assert!(fh.hash(&test_data[..0x68]) == 0xb827406e56e52147aa64e87730b45053);
    assert!(fh.hash(&test_data[..0x69]) == 0xf7c07cd7b54659b4e0fa9b6f876c67c4);
    assert!(fh.hash(&test_data[..0x6a]) == 0x249a2282072ef3290e137789b6397918);
    assert!(fh.hash(&test_data[..0x6b]) == 0x8ec980a5dfba8033af83b544866825d9);
    assert!(fh.hash(&test_data[..0x6c]) == 0xeffd0d6be048336bf51f346096cea90e);
    assert!(fh.hash(&test_data[..0x6d]) == 0x743958c67392f3459eccc4b03d4509b8);
    assert!(fh.hash(&test_data[..0x6e]) == 0x3d4ead5cdc0423f49c6b1772b314fd69);
    assert!(fh.hash(&test_data[..0x6f]) == 0xe1a67abb501b5febe0686f38ee215964);
    assert!(fh.hash(&test_data[..0x70]) == 0x980bc0179a5ffd74e70de96a053beff8);
    assert!(fh.hash(&test_data[..0x71]) == 0x426327d413ed8925f441df43c539e1de);
    assert!(fh.hash(&test_data[..0x72]) == 0x441ab6fe573769e60d2fb1bb5d2b70cb);
    assert!(fh.hash(&test_data[..0x73]) == 0xedadeb80ad2dbb1e586455dbee535f4d);
    assert!(fh.hash(&test_data[..0x74]) == 0xf49c2b8742471c62bdfd64bb697a7d9a);
    assert!(fh.hash(&test_data[..0x75]) == 0x0e2bb0091da73d6fe227ac910d0ff929);
    assert!(fh.hash(&test_data[..0x76]) == 0x2f38ef36ee76f013aea3d6ab77b4a92d);
    assert!(fh.hash(&test_data[..0x77]) == 0x812b397763acd48889ed19055024dc1b);
    assert!(fh.hash(&test_data[..0x78]) == 0x814cee548741e96992715789cfc905ad);
    assert!(fh.hash(&test_data[..0x79]) == 0x32e271accb857b3140201686e494c3be);
    assert!(fh.hash(&test_data[..0x7a]) == 0x93333372751d99e6307837ae6c74653f);
    assert!(fh.hash(&test_data[..0x7b]) == 0xa4b5706b9198301fb06ba0d49e2d796a);
    assert!(fh.hash(&test_data[..0x7c]) == 0x5cace7793572149cf2f8817aec2ff832);
    assert!(fh.hash(&test_data[..0x7d]) == 0x2807e6952b39447cfd43412078268e1f);
    assert!(fh.hash(&test_data[..0x7e]) == 0x2c6fdb32d030e19c70afe6bc399e0ea0);
    assert!(fh.hash(&test_data[..0x7f]) == 0x84878347cb3091a055024fb9d5beddbb);
}
