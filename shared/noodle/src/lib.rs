#![cfg_attr(not(feature = "std"), no_std)]
#![feature(const_generics)]
#![allow(incomplete_features)]

extern crate core;
extern crate alloc;

#[macro_use] pub mod tuple_match;
#[macro_use] pub mod tuple_gen;

use core::mem::MaybeUninit;
use core::convert::TryInto;
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::borrow::{Cow, ToOwned};
use alloc::collections::VecDeque;

/// Write the contents of `buf` into `self`. Used to allow custom adapters for
/// writing during serialization. Return `None` if `buf` cannot be fully
/// serialized
pub trait Writer {
    fn write(&mut self, buf: &[u8]) -> Option<()>;
}

/// Reader trait
pub trait Reader {
    fn read(&mut self, buf: &mut [u8]) -> Option<usize>;

    fn read_exact(&mut self, mut buf: &mut [u8]) -> Option<()> {
        while buf.len() > 0 {
            let bread = self.read(buf)?;
            buf = &mut buf[bread..];
        }
        Some(())
    }
}

/// A buffered reader + writer
pub struct BufferedIo<T: Writer + Reader> {
    /// The type which we can read and write from
    inner: T,

    /// Reader buffer
    read: VecDeque<u8>,

    /// Writer buffer
    write: VecDeque<u8>,
}

impl<T: Writer + Reader> BufferedIo<T> {
    /// Create a new buffered I/O object
    pub fn new(inner: T) -> Self {
        BufferedIo {
            inner: inner,
            read:  VecDeque::with_capacity(16 * 1024),
            write: VecDeque::with_capacity(16 * 1024),
        }
    }
    /// Flush the internal TX buffer
    pub fn flush(&mut self) -> Option<()> {
        let (front, back) = self.write.as_slices();
        if front.len() > 0 {
            self.inner.write(front)?;
        }
        if back.len() > 0 {
            self.inner.write(back)?;
        }
        self.write.clear();
        Some(())
    }
}

impl<T: Writer + Reader> Writer for BufferedIo<T> {
    /// Write the `buffer` contents to the buffered writer
    fn write(&mut self, buf: &[u8]) -> Option<()> {
        // Determine the space left in our write buffer
        let remain = self.write.capacity() - self.write.len();

        if buf.len() <= remain {
            // If there's enough room to buffer the data, just buffer it
            self.write.extend(buf);
        } else {
            // There's not enough room, flush the buffer and write everything
            // out
            self.flush()?;
            self.inner.write(buf)?;
        }

        Some(())
    }
}

impl<T: Writer + Reader> Reader for BufferedIo<T> {
    fn read(&mut self, buf: &mut [u8]) -> Option<usize> {
        let mut ptr = &mut buf[..];
        let mut tmp = [0u8; 2048];

        while ptr.len() > 0 {
            // Determine the amount we can copy from the internal buffer
            let to_copy = core::cmp::min(ptr.len(), self.read.len());

            // Read from our internal buffer
            ptr[..to_copy].iter_mut().for_each(|x| {
                *x = self.read.pop_front().unwrap();
            });
            ptr = &mut ptr[to_copy..];

            // Read complete
            if ptr.len() == 0 { break; }
            
            // We must have drained the internal buffer at this point
            assert!(self.read.len() == 0);

            // Get some more bytes into our internal buffer
            let bread = self.inner.read(&mut tmp)?;
            self.read.extend(&tmp[..bread]);
        }

        Some(buf.len())
    }
}

/// `Reader` implementation for types that implement `Read`
#[cfg(feature = "std")]
impl<T: std::io::Read> Reader for T {
    fn read(&mut self, buf: &mut [u8]) -> Option<usize> {
        self.read(buf).ok()
    }
}

/// `Writer` implementation for types that implement `Write`
#[cfg(feature = "std")]
impl<T: std::io::Write> Writer for T {
    fn write(&mut self, buf: &[u8]) -> Option<()> {
        self.write_all(buf).ok()
    }
}

/// Basic `Reader` implementation for slices of bytes
#[cfg(not(feature = "std"))]
impl Reader for &[u8] {
    fn read(&mut self, buf: &mut [u8]) -> Option<usize> {
        // Determine number of bytes we can read
        let to_read = core::cmp::min(buf.len(), self.len());

        // We literally can't do anything, this is an error
        if to_read == 0 { return None; }

        buf[..to_read].copy_from_slice(&self[..to_read]);
        *self = &self[to_read..];

        Some(to_read)
    }
}

/// Basic `Writer` implementation for vectors of bytes
#[cfg(not(feature = "std"))]
impl Writer for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> Option<()> {
        self.extend_from_slice(buf);
        Some(())
    }
}

/// Serialize a `self` into a writer
pub trait Serialize {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()>;
}

/// Deserialize a buffer, creating a Some(`Self`) if the deserialization
/// succeeds, otherwise a `None` is returned.
///
/// If deserialization fails at any point, all intermediate objects created
/// will be destroyed and `None` will be returned.
pub trait Deserialize: Sized {
    fn deserialize<R: Reader>(reader: &mut R) -> Option<Self>;
}

/// Implement `Serialize` trait for types which provide `to_le_bytes()`
macro_rules! serialize_le {
    // Serialize `$input_type` as an `$wire_type` by using `to_le_bytes()`
    // and `from_le_bytes()`. The `$input_type` gets converted to an
    // `$wire_type` via `TryInto`
    ($input_type:ty, $wire_type:ty) => {
        impl Serialize for $input_type {
            fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
                let wire: $wire_type = (*self).try_into()
                    .expect("Should never happen, input type to wire type");
                writer.write(&wire.to_le_bytes())
            }
        }

        impl Deserialize for $input_type {
            fn deserialize<R: Reader>(reader: &mut R) -> Option<Self> {
                // Read in the bytes for this type
                let mut arr = [0u8; core::mem::size_of::<$wire_type>()];
                reader.read_exact(&mut arr)?;

                // Convert the array of bytes into the `$wire_type`
                let wire_val = <$wire_type>::from_le_bytes(arr);

                // Try to convert the wire-format type into the desired type
                let converted: $input_type = wire_val.try_into().ok()?;

                // Return out the deserialized `Self`!
                Some(converted)
            }
        }
    };

    // Serialize an $input_type using `to_le_bytes()` and `from_le_bytes()`
    ($input_type:ty) => {
        serialize_le!($input_type, $input_type);
    };
}

// Implement serialization for all of the primitive types
serialize_le!(u8);
serialize_le!(u16);
serialize_le!(u32);
serialize_le!(u64);
serialize_le!(u128);
serialize_le!(i8);
serialize_le!(i16);
serialize_le!(i32);
serialize_le!(i64);
serialize_le!(i128);
serialize_le!(usize, u64);
serialize_le!(isize, i64);

impl Serialize for bool {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        writer.write(&[*self as u8])
    }
}

impl Deserialize for bool {
    fn deserialize<R: Reader>(reader: &mut R) -> Option<Self> {
        // Read in the bytes for this type
        let mut arr = [0u8; 1];
        reader.read_exact(&mut arr)?;
        Some(arr[0] != 0)
    }
}

/// Implement serialize for `&str`
impl Serialize for str {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        // Serialize the underlying bytes of the string
        Serialize::serialize(self.as_bytes(), writer)
    }
}

/// Implement serialize for `&str`
impl Serialize for &str {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        // Serialize the underlying bytes of the string
        Serialize::serialize(self.as_bytes(), writer)
    }
}

/// Implement serialize for `[T]`
impl<T: Serialize> Serialize for [T] {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        // Serialize the number of elements
        Serialize::serialize(&self.len(), writer)?;

        // Serialize all of the values
        self.iter().try_for_each(|x| Serialize::serialize(x, writer))
    }
}

/// Implement `Serialize` for `Option`
impl<T: Serialize> Serialize for Option<T> {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        if let Some(val) = self.as_ref() {
            // Serialize that this is a some type
            writer.write(&[1])?;

            // Serialize the underlying bytes of the value
            Serialize::serialize(val, writer)
        } else {
            // `None` value case
            writer.write(&[0])
        }
    }
}

/// Implement `Deserialize` for `Option`
impl<T: Deserialize> Deserialize for Option<T> {
    fn deserialize<R: Reader>(reader: &mut R) -> Option<Self> {
        // Get if this option is a `Some` value
        let is_some = <u8 as Deserialize>::deserialize(reader)? != 0;
        
        let ret = if is_some {
            // Deserialize payload
            Some(<T as Deserialize>::deserialize(reader)?)
        } else {
            None
        };

        Some(ret)
    }
}

/// Implement `Serialize` for `String`
impl Serialize for String {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        // Serialize the underlying bytes of the string
        Serialize::serialize(self.as_bytes(), writer)
    }
}

/// Implement `Deserialize` for `String`
impl Deserialize for String {
    fn deserialize<R: Reader>(reader: &mut R) -> Option<Self> {
        // Deserialize a vector of bytes
        let vec = <Vec<u8> as Deserialize>::deserialize(reader)?;

        // Convert it to a string and return it out
        let ret = String::from_utf8(vec).ok()?;

        Some(ret)
    }
}

/// Implement `Serialize` for types which can be `Cow`ed
impl<'a, T: 'a> Serialize for Cow<'a, T>
        where T: Serialize + ToOwned + ?Sized {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        Serialize::serialize(self.as_ref(), writer)
    }
}

/// Implement `Deserialize` for types which can be `Cow`ed
impl<'a, T: 'a> Deserialize for Cow<'a, T>
        where T: ToOwned + ?Sized,
              <T as ToOwned>::Owned: Deserialize {
    fn deserialize<R: Reader>(reader: &mut R) -> Option<Self> {
        // Deserialize into the owned type for the `Cow`
        let ret =
            <<T as ToOwned>::Owned as Deserialize>::deserialize(reader)?;
        Some(Cow::Owned(ret))
    }
}

/// Implement `Serialize` for `Box`
impl<T: Serialize> Serialize for Box<T> {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        Serialize::serialize(self.as_ref(), writer)
    }
}

/// Implement `Deserialize` for `Box`
impl<T: Deserialize> Deserialize for Box<T> {
    fn deserialize<R: Reader>(reader: &mut R) -> Option<Self> {
        let thing: T = Deserialize::deserialize(reader)?;
        Some(Box::new(thing))
    }
}

/// Implement `Serialize` for `Arc`
impl<T: Serialize> Serialize for Arc<T> {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        Serialize::serialize(self.as_ref(), writer)
    }
}

/// Implement `Deserialize` for `Arc`
impl<T: Deserialize> Deserialize for Arc<T> {
    fn deserialize<R: Reader>(reader: &mut R) -> Option<Self> {
        let thing: T = Deserialize::deserialize(reader)?;
        Some(Arc::new(thing))
    }
}

/// Implement `Serialize` for `Vec<T>`
impl<T: Serialize> Serialize for Vec<T> {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        // Serialize the number of elements
        Serialize::serialize(&self.len(), writer)?;

        // Serialize all of the values
        self.iter().try_for_each(|x| Serialize::serialize(x, writer))
    }
}

/// Implement `Deserialize` for `Vec`s that contain all `Deserialize` types
impl<T: Deserialize> Deserialize for Vec<T> {
    fn deserialize<R: Reader>(reader: &mut R) -> Option<Self> {
        // Get the length of the vector in elements
        let len = <usize as Deserialize>::deserialize(reader)?;

        // Allocate the vector we're going to return
        let mut vec = Vec::with_capacity(len);

        // Deserialize all the components
        for _ in 0..len {
            vec.push(<T as Deserialize>::deserialize(reader)?);
        }

        Some(vec)
    }
}

/// Implement `Serialize` trait for arrays of types which implement `Serialize`
impl<T: Serialize, const N: usize> Serialize for [T; N] {
    fn serialize<W: Writer>(&self, writer: &mut W) -> Option<()> {
        // Serialize all of the values
        self.iter().try_for_each(|x| Serialize::serialize(x, writer))
    }
}

impl<T: Deserialize, const N: usize> Deserialize for [T; N] {
    fn deserialize<R: Reader>(_reader: &mut R) -> Option<Self> {
        // Deserialize the array
        let mut arr: MaybeUninit<[T; N]> = MaybeUninit::uninit();

        unsafe {
            // Get mutable access to the array
            let ptr: *mut T = arr.as_mut_ptr() as *mut T;

            // Deserialize each element
            let mut deserialized = 0;
            for ii in 0..N {
                if let Some(x) = Deserialize::deserialize(_reader) {
                    ptr.offset(ii as isize).write(x);
                    deserialized += 1;
                } else {
                    // Failed to deserialize, break out
                    break;
                }
            }

            // Check if we deserialized everything
            if deserialized != N {
                // Drop things that were partially deserialized
                for ii in 0..deserialized {
                    core::ptr::drop_in_place(ptr.offset(ii as isize));
                }

                // Return failure
                return None;
            }
        }

        Some(unsafe { arr.assume_init() })
    }
}

/// Implement serialize and deserialize on an enum or structure definition.
/// 
/// This is used by just wrapping a structure definition like:
///
/// `noodle!(serialize, deserialize, struct Foo { bar: u32 })`
///
/// This can be used on any structure or enum definition and automatically
/// implements the serialize and deserialize traits for it by enumerating every
/// field in the structure (or enum variant) and serializing it out in
/// definition order.
///
/// This all looks really complicated, but it's really just a lot of copied
/// and pasted code that can represent a structure or enum shape in macros.
/// These macros destruct all possible structs and enums and gives us "access"
/// to the inner field names, ordering, and types. This allows us to invoke
/// the `serialize` or `deserialize` routines for every member of the
/// structure. It's that simple!
#[macro_export]
macro_rules! noodle {
    // Create a new struct with serialize and deserialize implemented
    (serialize, deserialize,
        $(#[$attr:meta])* $vis:vis struct $structname:ident $(<$($generic:tt),*>)?
            // Named struct
            $({
                $(
                    $(#[$named_attr:meta])*
                        $named_vis:vis $named_field:ident: $named_type:ty
                ),*$(,)?
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta:meta])* $tuple_vis:vis $tuple_typ:ty
                ),*$(,)? 
            );)?

            // Eat semicolons
            $(;)?
    ) => {
        noodle!(define_struct,
            $(#[$attr])* $vis struct $structname $(<$($generic),*>)?
            // Named struct
            $({
                $(
                    $(#[$named_attr])*
                        $named_vis $named_field: $named_type
                ),*
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta])* $tuple_vis $tuple_typ
                ),*
            );)?
        );
        noodle!(impl_serialize_struct,
            $(#[$attr])* $vis struct $structname $(<$($generic),*>)?
            // Named struct
            $({
                $(
                    $(#[$named_attr])*
                        $named_vis $named_field: $named_type
                ),*
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta])* $tuple_vis $tuple_typ
                ),*
            );)?
        );
        noodle!(impl_deserialize_struct,
            $(#[$attr])* $vis struct $structname $(<$($generic),*>)?
            // Named struct
            $({
                $(
                    $(#[$named_attr])*
                        $named_vis $named_field: $named_type
                ),*
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta])* $tuple_vis $tuple_typ
                ),*
            );)?
        );
    };

    // Define an empty structure
    (define_struct,
        $(#[$attr:meta])* $vis:vis struct $structname:ident $(<$($generic:tt),*>)?
    ) => {
        $(#[$attr])* $vis struct $structname $(<$($generic),*>)?;
    };

    // Define a structure
    (define_struct,
        $(#[$attr:meta])* $vis:vis struct $structname:ident $(<$($generic:tt),*>)?
            // Named struct
            $({
                $(
                    $(#[$named_attr:meta])*
                        $named_vis:vis $named_field:ident: $named_type:ty
                ),*$(,)?
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta:meta])* $tuple_vis:vis $tuple_typ:ty
                ),*$(,)? 
            );)?
    ) => {
        $(#[$attr])* $vis struct $structname $(<$($generic),*>)?
        // Named struct
        $({
            $(
                $(#[$named_attr])*
                    $named_vis $named_field: $named_type
            ),*
        })?

        // Named tuple
        $((
            $(
                $(#[$tuple_meta])* $tuple_vis $tuple_typ
            ),*
        );)?
    };

    // Implement serialization for a structure
    (impl_serialize_struct,
        $(#[$attr:meta])* $vis:vis struct $structname:ident $(<$($generic:tt),*>)?
            // Named struct
            $({
                $(
                    $(#[$named_attr:meta])*
                        $named_vis:vis $named_field:ident: $named_type:ty
                ),*$(,)?
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta:meta])* $tuple_vis:vis $tuple_typ:ty
                ),*$(,)? 
            );)?
    ) => {
        impl $(<$($generic),*>)? Serialize for $structname $(<$($generic),*>)? {
            fn serialize<W: Writer>(&self, _writer: &mut W) -> Option<()> {
                // Named struct
                $(
                    $(
                        Serialize::serialize(&self.$named_field, _writer)?;
                    )*
                )?

                // Named tuple
                handle_serialize_named_tuple!(
                    self, _writer $($(, $tuple_typ)*)?);

                Some(())
            }
        }
    };

    // Implement deserialization for a field-less structs
    (impl_deserialize_struct,
        $(#[$attr:meta])* $vis:vis struct $structname:ident $(<$($generic:tt),*>)?
    ) => {
        impl $(<$($generic),*>)? Deserialize for $structname $(<$($generic),*>)? {
            fn deserialize<R: Reader>(_reader: &mut R) -> Option<Self> {
                Some($structname)
            }
        }
    };

    // Implement deserialization for a structure
    (impl_deserialize_struct,
        $(#[$attr:meta])* $vis:vis struct $structname:ident $(<$($generic:tt),*>)?
            // Named struct
            $({
                $(
                    $(#[$named_attr:meta])*
                        $named_vis:vis $named_field:ident: $named_type:ty
                ),*$(,)?
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta:meta])* $tuple_vis:vis $tuple_typ:ty
                ),*$(,)? 
            );)?
    ) => {
        impl $(<$($generic),*>)? Deserialize for $structname $(<$($generic),*>)? {
            fn deserialize<R: Reader>(_reader: &mut R) -> Option<Self> {
                // Named struct
                $(if true {
                    
                    let ret = $structname {
                        $(
                            $named_field: Deserialize::deserialize(_reader)?,
                        )*
                    };

                    return Some(ret);
                })?

                // Named tuple
                $(if true {
                    let ret = $structname(
                        $(
                            <$tuple_typ as Deserialize>::deserialize(_reader)?,
                        )*
                    );

                    return Some(ret);
                })?

                // Not reachable
                unreachable!("How'd you get here?");
            }
        }
    };

    // Create a new enum with serialize and deserialize implemented
    (serialize, deserialize,
        $(#[$attr:meta])* $vis:vis enum $enumname:ident $(<$($generic:tt),*>)? {
            // Go through each variant in the enum
            $(
                // Variant attributes
                $(#[$variant_attr:meta])*

                // Identifier for the enum variant, always present
                $variant_ident:ident
                
                // An enum item struct
                $({
                    $(
                        $(#[$named_attr:meta])*
                            $named_field:ident: $named_type:ty
                    ),*$(,)?
                })?

                // An enum item tuple
                $((
                    $(
                        $(#[$tuple_meta:meta])* $tuple_typ:ty
                    ),*$(,)? 
                ))?

                // An enum discriminant
                $(= $expr:expr)?
            ),*$(,)?
        }
    ) => {
        noodle!(define_enum,
            $(#[$attr])* $vis enum $enumname $(<$($generic),*>)? {
                // Go through each variant in the enum
                $(
                    // Variant attributes
                    $(#[$variant_attr])*

                    // Identifier for the enum variant, always present
                    $variant_ident
                    
                    // An enum item struct
                    $({
                        $(
                            $(#[$named_attr])* $named_field: $named_type
                        ),*
                    })?

                    // An enum item tuple
                    $((
                        $(
                            $(#[$tuple_meta])* $tuple_typ
                        ),*
                    ))?

                    // An enum discriminant
                    $(= $expr)?
                ),*
            });
        noodle!(impl_serialize_enum,
            $(#[$attr])* $vis enum $enumname $(<$($generic),*>)? {
                // Go through each variant in the enum
                $(
                    // Variant attributes
                    $(#[$variant_attr])*

                    // Identifier for the enum variant, always present
                    $variant_ident
                    
                    // An enum item struct
                    $({
                        $(
                            $(#[$named_attr])* $named_field: $named_type
                        ),*
                    })?

                    // An enum item tuple
                    $((
                        $(
                            $(#[$tuple_meta])* $tuple_typ
                        ),*
                    ))?

                    // An enum discriminant
                    $(= $expr)?
                ),*
            });
        noodle!(impl_deserialize_enum,
            $(#[$attr])* $vis enum $enumname $(<$($generic),*>)? {
                // Go through each variant in the enum
                $(
                    // Variant attributes
                    $(#[$variant_attr])*

                    // Identifier for the enum variant, always present
                    $variant_ident
                    
                    // An enum item struct
                    $({
                        $(
                            $(#[$named_attr])* $named_field: $named_type
                        ),*
                    })?

                    // An enum item tuple
                    $((
                        $(
                            $(#[$tuple_meta])* $tuple_typ
                        ),*
                    ))?

                    // An enum discriminant
                    $(= $expr)?
                ),*
            });
    };

    (define_enum,
        $(#[$attr:meta])* $vis:vis enum $enumname:ident $(<$($generic:tt),*>)? {
            // Go through each variant in the enum
            $(
                // Variant attributes
                $(#[$variant_attr:meta])*

                // Identifier for the enum variant, always present
                $variant_ident:ident
                
                // An enum item struct
                $({
                    $(
                        $(#[$named_attr:meta])*
                            $named_field:ident: $named_type:ty
                    ),*$(,)?
                })?

                // An enum item tuple
                $((
                    $(
                        $(#[$tuple_meta:meta])* $tuple_typ:ty
                    ),*$(,)? 
                ))?

                // An enum discriminant
                $(= $expr:expr)?
            ),*$(,)?
        }) => {
            // Just define the enum as is
            $(#[$attr])* $vis enum $enumname $(<$($generic),*>)? {
                // Go through each variant in the enum
                $(
                    // Variant attributes
                    $(#[$variant_attr])*

                    // Identifier for the enum variant, always present
                    $variant_ident
                    
                    // An enum item struct
                    $({
                        $(
                            $(#[$named_attr])* $named_field: $named_type
                        ),*
                    })?

                    // An enum item tuple
                    $((
                        $(
                            $(#[$tuple_meta])* $tuple_typ
                        ),*
                    ))?

                    // An enum discriminant
                    $(= $expr)?
                ),*
            }
    };

    (impl_serialize_enum,
        $(#[$attr:meta])* $vis:vis enum $enumname:ident $(<$($generic:tt),*>)? {
            // Go through each variant in the enum
            $(
                // Variant attributes
                $(#[$variant_attr:meta])*

                // Identifier for the enum variant, always present
                $variant_ident:ident
                
                // An enum item struct
                $({
                    $(
                        $(#[$named_attr:meta])*
                            $named_field:ident: $named_type:ty
                    ),*$(,)?
                })?

                // An enum item tuple
                $((
                    $(
                        $(#[$tuple_meta:meta])* $tuple_typ:ty
                    ),*$(,)? 
                ))?

                // An enum discriminant
                $(= $expr:expr)?
            ),*$(,)?
        }) => {
        impl $(<$($generic),*>)? Serialize for $enumname $(<$($generic),*>)? {
            fn serialize<W: Writer>(&self, _writer: &mut W) -> Option<()> {
                let mut _count = 0u32;

                // Go through each variant
                $(
                    handle_serialize_enum_variants!(
                        self, $enumname, $variant_ident, _writer, &_count,
                        $({$($named_field),*})? $(($($tuple_typ),*))?);

                    _count += 1;
                )*

                Some(())
            }
        }
    };

    (impl_deserialize_enum,
        $(#[$attr:meta])* $vis:vis enum $enumname:ident  $(<$($generic:tt),*>)? {
            // Go through each variant in the enum
            $(
                // Variant attributes
                $(#[$variant_attr:meta])*

                // Identifier for the enum variant, always present
                $variant_ident:ident
                
                // An enum item struct
                $({
                    $(
                        $(#[$named_attr:meta])*
                            $named_field:ident: $named_type:ty
                    ),*$(,)?
                })?

                // An enum item tuple
                $((
                    $(
                        $(#[$tuple_meta:meta])* $tuple_typ:ty
                    ),*$(,)? 
                ))?

                // An enum discriminant
                $(= $expr:expr)?
            ),*$(,)?
        }) => {
        impl $(<$($generic),*>)? Deserialize for $enumname $(<$($generic),*>)? {
            fn deserialize<R: Reader>(reader: &mut R) -> Option<Self> {
                // Count tracking enum variants
                let mut _count = 0u32;

                // Get the enum variant
                let _variant = u32::deserialize(reader)?;

                // Go through each variant
                $(
                    handle_deserialize_enum_variants!(
                        _variant, $enumname, $variant_ident,
                        reader, _count,
                        $({$($named_field),*})? $(($($tuple_typ),*))?);

                    _count += 1;
                )*

                // Failed to find a matching variant, return `None`
                None
            }
        }
    };
}

/// Handles serializing of the 3 different enum variant types. Enum struct
/// variants, enum tuple variants, and enum discriminant/bare variants
#[macro_export]
macro_rules! handle_serialize_enum_variants {
    // Named enum variants
    ($self:ident, $enumname:ident, $variant_ident:ident,
            $buf:expr, $count:expr, {$($named_field:ident),*}) => {
        if let $enumname::$variant_ident { $($named_field),* } = $self {
            // Serialize the variant ID
            Serialize::serialize($count, $buf)?;

            // Serialize all fields
            $(
                Serialize::serialize($named_field, $buf)?;
            )*
        }
    };

    // Tuple enum variants
    ($self:ident, $enumname:ident, $variant_ident:ident,
            $buf:expr, $count:expr, ($($tuple_typ:ty),*)) => {
        handle_serialize_tuple_match!($self, $count, $buf, $enumname,
            $variant_ident $(, $tuple_typ)*);
    };

    // Discriminant or empty enum variants
    ($self:ident, $enumname:ident, $variant_ident:ident,
            $buf:expr, $count:expr,) => {
        if let $enumname::$variant_ident = $self {
            // Serialize the variant ID
            Serialize::serialize($count, $buf)?;
        }
    };
}

/// Handles deserializing of the 3 different enum variant types. Enum struct
/// variants, enum tuple variants, and enum discriminant/bare variants
#[macro_export]
macro_rules! handle_deserialize_enum_variants {
    // Named enum variants
    ($variant:ident, $enumname:ident, $variant_ident:ident, $reader:expr,
            $count:expr, {$($named_field:ident),*}) => {
        if $count == $variant {
            // Construct the enum
            let ret = $enumname::$variant_ident {
                $(
                    $named_field: Deserialize::deserialize($reader)?,
                )*
            };

            return Some(ret);
        }
    };

    // Tuple enum variants
    ($variant:ident, $enumname:ident, $variant_ident:ident, $reader:expr,
            $count:expr, ($($tuple_typ:ty),*)) => {
        if $count == $variant {
            // Construct the enum
            let ret = $enumname::$variant_ident (
                $(
                    <$tuple_typ as Deserialize>::deserialize($reader)?,
                )*
            );

            return Some(ret);
        }
    };

    // Discriminant or empty enum variants
    ($variant:ident, $enumname:ident, $variant_ident:ident, $reader:expr,
            $count:expr,) => {
        if $count == $variant {
            // Construct the enum
            let ret = $enumname::$variant_ident;
            return Some(ret);
        }
    };
}

#[cfg(test)]
mod test {
    use crate::*;

    // Serialize a payload and then validate that when it is deserialized it
    // matches the serialized payload identically
    macro_rules! test_serdes {
        ($payload_ty:ty, $payload:expr) => {
            // Allocate serialization buffer
            let mut buf = Vec::new();

            // Serialize `payload`
            $payload.serialize(&mut buf).unwrap();

            // Allocate a pointer to the serialized buffer
            let mut ptr = &buf[..];

            // Deserialize the payload
            let deser_payload = <$payload_ty>::deserialize(&mut ptr)
                .expect("Failed to deserialize payload");

            // Make sure all bytes were consumed from the serialized buffer
            assert!(ptr.len() == 0,
                "Deserialization did not consume all serialized bytes");

            // Make sure the original payload and the deserialized payload
            // match
            assert!($payload == deser_payload,
                "Serialization and deserialization did not match original");
        }
    }

    #[test]
    fn test_enums() {
        // Not constructable, but we should handle this empty enum case
        noodle!(serialize, deserialize,
            enum TestA {}
        );

        // Basic enum
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            enum TestB {
                Apples,
                Bananas,
            }
        );
        test_serdes!(TestB, TestB::Apples);
        test_serdes!(TestB, TestB::Bananas);

        // Enum with a discriminant
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            enum TestC {
                Apples = 6,
                Bananas
            }
        );
        test_serdes!(TestC, TestC::Apples);
        test_serdes!(TestC, TestC::Bananas);

        // Enum with all types of variants, and some extra attributes at each
        // level to test attribute handling
        noodle!(serialize, deserialize,
            /// Big doc comment here
            /// with many lines
            /// you know?
            #[derive(PartialEq)]
            enum TestD {
                #[cfg(test)]
                Apples {},
                Cars,
                Bananas {
                    /* comment
                     */
                    #[cfg(test)]
                    x: u32,
                    /// doc comment
                    z: i32
                },
                // Another comment
                Cake(),
                Weird(,),
                Cakes(u32),
                Foopie(i8, i32,),
                Testing(i128, i64),
                Arrayz([u8; 4]),
                Lotsotuple(i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8),
            }
        );
        test_serdes!(TestD, TestD::Apples {});
        test_serdes!(TestD, TestD::Cars);
        test_serdes!(TestD, TestD::Bananas { x: 932923, z: -348192 });
        test_serdes!(TestD, TestD::Cake());
        test_serdes!(TestD, TestD::Weird());
        test_serdes!(TestD, TestD::Cakes(0x13371337));
        test_serdes!(TestD, TestD::Foopie(-9, 19));
        test_serdes!(TestD, TestD::Testing(0xc0c0c0c0c0c0c0c0c0c0c0, -10000));
        test_serdes!(TestD, TestD::Arrayz([9; 4]));
        test_serdes!(TestD, TestD::Lotsotuple(0,0,0,0,0,5,0,0,0,0,0,0,0,9,0,0));

        // Enum with a discriminant
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            enum TestE<'a> {
                Bananas(Cow<'a, str>),
                Scoops,
            }
        );
        test_serdes!(TestE, TestE::Bananas(Cow::Borrowed("asdf")));
        test_serdes!(TestE, TestE::Scoops);
    }

    #[test]
    fn test_struct() {
        // Empty struct
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestA {}
        );
        test_serdes!(TestA, TestA {});

        // Standard struct
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestB {
                foo: u32,
                bar: i32,
            }
        );
        test_serdes!(TestB, TestB { foo: 4343, bar: -234 });

        // Standard struct with some arrays
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestC {
                foo: u32,
                pub bar: [u32; 8],
            }
        );
        test_serdes!(TestC, TestC { foo: 4343, bar: [10; 8] });

        // Bare struct
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestD;
        );
        test_serdes!(TestD, TestD);
        
        // Empty named tuple
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestE();
        );
        test_serdes!(TestE, TestE());

        // Named tuple
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestF(u32, i128);
        );
        test_serdes!(TestF, TestF(!0, -42934822412));

        // Named tuple with trailing comma and a generic
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestG(u32, i128,);
        );
        test_serdes!(TestG, TestG(4, 6));

        // Named tuple with array and nested structure
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestH(u32, [i8; 4], TestG);
        );
        test_serdes!(TestH, TestH(99, [3; 4], TestG(5, -23)));

        // Structure with lifetimes
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestI<'a, 'b>(Cow<'a, str>, Cow<'b, str>);
        );
        test_serdes!(TestI, TestI(Cow::Borrowed("asdf"), Cow::Borrowed("a")));
    }
}

