extern crate byteorder;
use byteorder::{ByteOrder, LittleEndian};

// first u32 is the old offset in resource section
// second u32 is the new offset in the generated resource section
#[derive(Debug)]
pub enum Robject {
    Null,
    Table(u32, u32),
    NameEntry(u32, u32),
    IdEntry(u32, u32),
    Leaf(u32, u32)
}

//--------------------------------------------------------------------------------------------------------
// Resource Directory Table - RDT
//--------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Rtable {
	pub characteristics: u32,
	pub timestamp: u32,
	pub maj_ver: u16,
	pub min_ver: u16,
	pub names: u16,
	pub ids: u16
}

impl Rtable {
    pub fn new() -> Rtable {
        Rtable {
            characteristics: 0,
            timestamp: 0,
            maj_ver: 0,
            min_ver: 0,
            names: 0,
            ids: 0
        }
    }

	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes: Vec<u8> = vec![0u8;16];
		LittleEndian::write_u32(&mut bytes[..4], self.characteristics);
		LittleEndian::write_u32(&mut bytes[4..8], self.timestamp);
		LittleEndian::write_u16(&mut bytes[8..10], self.maj_ver);
		LittleEndian::write_u16(&mut bytes[10..12], self.min_ver);
		LittleEndian::write_u16(&mut bytes[12..14], self.names);
		LittleEndian::write_u16(&mut bytes[14..16], self.ids);
		bytes
	}
	pub fn from_bytes(&mut self, buf: &[u8]) -> Result<u32, String> {
		if buf.len() >= 16 {
			self.characteristics = LittleEndian::read_u32(&buf[..4]);
			self.timestamp = LittleEndian::read_u32(&buf[4..8]);
			self.maj_ver = LittleEndian::read_u16(&buf[8..10]);
			self.min_ver = LittleEndian::read_u16(&buf[10..12]);
			self.names = LittleEndian::read_u16(&buf[12..14]);
			self.ids = LittleEndian::read_u16(&buf[14..16]);
			return Ok(16)
		}
		Err(format!("[Rtable::from_bytes] Invalid buffer length: {} bytes; should be at least 16", buf.len()))
	}
	
    pub fn new_from_bytes(buf: &[u8]) -> Result<Rtable, String> {
        let mut t = Rtable::new();
        match t.from_bytes(buf) {
            Ok(_) => return Ok(t),
            Err(msg) => return Err(msg)
        }
    }
}

#[cfg(test)]
mod rtable_test {
	use super::*;

	#[test]
	fn verify_to_bytes() {
		let a = Rtable {
			characteristics: 0x04030201,
			timestamp: 0x08070605,
			maj_ver: 0x0A09,
			min_ver: 0x0C0B,
			names: 0x0E0D,
			ids: 0x100F
		};
		assert_eq!(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], a.to_bytes());
	}

	#[test]
	fn verify_from_bytes() {
		let values: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
		let mut a = Rtable {
			characteristics: 0,
			timestamp: 0,
			maj_ver: 0,
			min_ver: 0,
			names: 0,
			ids: 0
		};
		let res = a.from_bytes(&values[..16]);
        match res {
            Ok(s) => assert_eq!(16, s),
            Err(_) => assert!(false)
        }
		let invres = a.from_bytes(&values[..15]);
        match invres {
            Ok(_) => assert!(false),
            Err(_) => assert!(true)
        }
		assert_eq!(a.characteristics, 0x04030201);
		assert_eq!(a.timestamp, 0x08070605);
		assert_eq!(a.maj_ver, 0x0A09);
		assert_eq!(a.min_ver, 0x0C0B);
		assert_eq!(a.names, 0x0E0D);
		assert_eq!(a.ids, 0x100F);
	}
}

//--------------------------------------------------------------------------------------------------------
// Resource string
//--------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Rstring {
	pub size: u16,
	pub bytes: Vec<u16>,
    pub utf8: Option<String>
}

impl Rstring {
    pub fn new() -> Rstring {
        Rstring {
            size: 0,
            bytes: vec![],
            utf8: None
        }
    }

	pub fn to_bytes(&self) -> Vec<u8> {
		let mut buf: Vec<u8> = vec![];
		let mut tmp = vec![0u8;4];
		LittleEndian::write_u16(&mut tmp[..2], self.size);
		buf.push(tmp[0]);
		buf.push(tmp[1]);
        for i in 0..self.size as usize {
            let ch = self.bytes[i];
            buf.push(ch.to_le_bytes()[0]);
            buf.push(ch.to_le_bytes()[1]);
        }
		//buf.extend_from_slice(&self.bytes[..]);
		buf
	}
	
	pub fn from_bytes(&mut self, buf: &[u8]) -> Result<u32, String> {
		if buf.len() > 2 {
            let s = LittleEndian::read_u16(&buf[..2]);
			self.size = s;
            
            for i in 0..s as usize {
                self.bytes.push(LittleEndian::read_u16(&buf[2+i*2..4+i*2]));
            }

            let utf = String::from_utf16(&self.bytes[..]);
            if let Ok(s) = utf {
                self.utf8 = Some(s);
            }
			return Ok(buf.len() as u32)
		}
		Err(format!("[Rstring::from_bytes] Buffer is too short: {} bytes", buf.len()))
	}

	pub fn new_from_bytes(buf: &[u8]) -> Result<Rstring, String> {
        let mut s = Rstring::new();
        let res = s.from_bytes(buf);
        match res {
            Ok(_) => return Ok(s),
            Err(msg) => return Err(msg)
        }
    }

	pub fn from_raw_bytes(&mut self, buf: &[u8]) -> Result<u32, String> {
        if buf.len() == 0 || buf.len() > 0xFFFF {
            return Err(format!("[Rstring::from_raw_bytes] Invalid slice length: 0x{:X?}!", buf.len()));
        }
		self.size = buf.len() as u16;
        for i in 0..self.size as usize {
            self.bytes.push(LittleEndian::read_u16(&buf[i*2..2+i*2]));
        }

        let utf = String::from_utf16(&self.bytes[..]);
        if let Ok(s) = utf {
            self.utf8 = Some(s);
        }
		Ok(self.size as u32)
	}

}

#[cfg(test)]
mod rstring_test {
	use super::*;

	#[test]
	fn verify_to_bytes() {
		let a = Rstring {
			size: 8,
			bytes: vec![0x30, 0, 0x31, 0, 0x32, 0, 0, 0]
		};
		assert_eq!(vec![8, 0, 0x30, 0, 0x31, 0, 0x32, 0, 0, 0], a.to_bytes());
	}

	#[test]
	fn verify_from_bytes() {
        let bytes: Vec<u8> = vec![10, 0, 0x30, 0, 0x31, 0, 0x32, 0, 0x33, 0, 0, 0];
		let mut a = Rstring {
			size: 0,
			bytes: vec![]
		};

        let res = a.from_bytes(&bytes[..]);
        match res {
            Ok(s) => assert_eq!(s as usize, bytes.len()),
            Err(_) => assert!(false)
        }
		assert_eq!(a.size, 10);
        assert_eq!(a.bytes, vec![0x30, 0, 0x31, 0, 0x32, 0, 0x33, 0, 0, 0]);

        let invres = a.from_bytes(&bytes[1..]);
        match invres {
            Err(_) => assert!(true),
            Ok(_) => assert!(false)
        }
	}

	#[test]
	fn verify_from_raw_bytes() {
        let bytes: Vec<u8> = vec![0x30, 0, 0x31, 0, 0x32, 0, 0x33, 0, 0, 0];
		let mut a = Rstring {
			size: 0,
			bytes: vec![]
		};

        let res = a.from_raw_bytes(&bytes[..]);
        match res {
            Ok(s) => assert_eq!(s as usize, bytes.len()),
            Err(_) => assert!(false)
        }
		assert_eq!(a.size, 10);
        assert_eq!(a.bytes, vec![0x30, 0, 0x31, 0, 0x32, 0, 0x33, 0, 0, 0]);

        let invres = a.from_raw_bytes(&[]);
        match invres {
            Err(_) => assert!(true),
            Ok(_) => assert!(false)
        }
	}
}

//--------------------------------------------------------------------------------------------------------
// Resource Directory Entry - RDE
//--------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub enum RDE {
    Unknown(u32),
	TypeString(u32),
	TypeId(u32)
}

#[derive(Debug)]
pub struct Rentry {
	pub typ: RDE,
	pub offset: u32,
    pub s: Option<Rstring>,
    pub data: Option<Rdata>
}

impl Rentry {
    pub fn new(entry_type: RDE) -> Rentry {
        Rentry {
            typ: entry_type,
            offset: 0,
            s: None,
            data: None
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
		let mut bytes: Vec<u8> = vec![0u8;8];
		match self.typ {
			RDE::TypeString(v) => LittleEndian::write_u32(&mut bytes[..4], v),
			RDE::TypeId(v) => LittleEndian::write_u32(&mut bytes[..4], v),
            RDE::Unknown(v) => LittleEndian::write_u32(&mut bytes[..4], v) 
		}
		LittleEndian::write_u32(&mut bytes[4..8], self.offset);
		bytes
	}
	
	pub fn from_bytes(&mut self, buf: &[u8]) -> Result<u32, String> {
		if buf.len() >= 8 {
			match self.typ {
				RDE::TypeString(_) => {
                    self.typ = RDE::TypeString(LittleEndian::read_u32(&buf[..4]));
                },
				RDE::TypeId(_) => self.typ = RDE::TypeId(LittleEndian::read_u32(&buf[..4])),
                RDE::Unknown(_) => self.typ = RDE::Unknown(LittleEndian::read_u32(&buf[..4]))
			}
			self.offset = LittleEndian::read_u32(&buf[4..8]);
            return Ok(8);
		}
		Err(format!("[Rentry::from_bytes] Buffer length is less than structure size!"))
	}
	
    pub fn new_from_bytes(entry_type: RDE, buf: &[u8], ofs: usize) -> Result<Rentry, String> {
        let mut e = Rentry::new(entry_type);
        match e.from_bytes(&buf[ofs..ofs+8]) {
            Ok(_) => {
                if let RDE::TypeString(_) = e.typ {
                    let name_string_offset = e.get_name_offset();
                    if let Ok(nofs) = name_string_offset {
                        let name_string = Rstring::new_from_bytes(&buf[nofs as usize..])?;
                        e.s = Some(name_string);
                    }
                }
                // If it's an offset to data and not table then add the data in the entry structure
                if let None = e.is_table_offset() {
                    let data = Rdata::new_from_bytes(&buf[e.offset as usize..])?;
                    e.data = Some(data);
                }
                return Ok(e);
            },

            Err(msg) => return Err(msg)
        }
    }

	pub fn is_table_offset(&self) -> Option<u32> {
		if self.offset & 0x80000000 != 0 {
			return Some(self.offset & 0x7FFFFFFF);
		}
		None
	}

	pub fn get_name_offset(&self) -> Result<u32, String> {
        match self.typ {
            RDE::TypeString(o) => {
                if o & 0x80000000 != 0 {
                    return Ok(o & 0x7FFFFFFF);
                } else {
                    return Err(format!("[Rentry::get_name_offset] Not a name offset: {:X?}", o));
                }
            },
            _ => return Err(format!("[Rentry::get_name_offset] Not a named entry!"))
        }
	}
}

#[cfg(test)]
mod rentry_test {
	use super::*;

	#[test]
	fn verify_as_bytes() {
		let a = Rentry {
			typ: RDE::TypeString(0x04030201),
			offset: 0x08070605,
            s: None
		};
		assert_eq!(vec![1, 2, 3, 4, 5, 6, 7, 8], a.as_bytes());
		let b = Rentry {
			typ: RDE::TypeId(0x04030201),
			offset: 0x08070605,
            s: None
		};
		assert_eq!(vec![1, 2, 3, 4, 5, 6, 7, 8], b.as_bytes());
	}

	#[test]
	fn verify_from_bytes() {
		let values: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
		let mut a = Rentry {
			typ: RDE::TypeString(0),
			offset: 0,
            s: None
		};
		let res = a.from_bytes(&values[..8]);
		assert_eq!(res, Result::Ok(8));
		match a.typ {
			RDE::TypeString(v) => assert_eq!(v, 0x04030201),
			_ => assert!(false)
		}
		assert_eq!(a.offset, 0x08070605);
		
		let mut b = Rentry {
			typ: RDE::TypeId(0),
			offset: 0,
            s: None
		};
		let res = b.from_bytes(&values[..8]);
		assert_eq!(res, Result::Ok(8));
		match b.typ {
			RDE::TypeId(v) => assert_eq!(v, 0x04030201),
			_ => assert!(false)
		}
		assert_eq!(a.offset, 0x08070605);

		//assert_eq!(a.characteristics, 0x04030201);
		//assert_eq!(a.timestamp, 0x08070605);
		//assert_eq!(a.maj_ver, 0x0A09);
		//assert_eq!(a.min_ver, 0x0C0B);
		//assert_eq!(a.names, 0x0E0D);
		//assert_eq!(a.ids, 0x100F);
	}

	#[test]
	fn verify_is_table_offset() {
		let a = Rentry {
			typ: RDE::TypeString(0x04030201),
			offset: 0x88070605,
            s: None
		};
        match a.is_table_offset() {
            Some(o) => assert_eq!(o, 0x8070605),
            None => assert!(false)
        }
		
		let b = Rentry {
			typ: RDE::TypeString(0x04030201),
			offset: 0,
            s: None
		};
        match a.is_table_offset() {
            Some(_) => assert!(false),
            None => assert!(true)
        }
	}
}

//--------------------------------------------------------------------------------------------------------
// Resource Data - RD
//--------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Rdata {
	pub rva: u32,
	pub size: u32,
    pub cp: u32,
}

impl Rdata {
    pub fn new() -> Rdata {
        Rdata {
            rva: 0,
            size: 0,
            cp: 0
        }
    }

	pub fn as_bytes(&self) -> Vec<u8> {
		let mut bytes: Vec<u8> = vec![0u8;16];
		LittleEndian::write_u32(&mut bytes[0..4], self.rva);
		LittleEndian::write_u32(&mut bytes[4..8], self.size);
		LittleEndian::write_u32(&mut bytes[8..12], self.cp);
		LittleEndian::write_u32(&mut bytes[12..16], 0);
		bytes
	}
	
	pub fn from_bytes(&mut self, buf: &[u8]) -> Result<u32, String> {
		if buf.len() >= 16 {
			let reserved = LittleEndian::read_u32(&buf[12..16]);
            if reserved != 0 {
                return Err(format!("[Rdata::from_bytes] Reserved field is not zero!"));
            }
			self.rva = LittleEndian::read_u32(&buf[0..4]);
			self.size = LittleEndian::read_u32(&buf[4..8]);
			self.cp = LittleEndian::read_u32(&buf[8..12]);
			return Ok(16);
		}
		Err(format!("[Rdata::from_bytes] Buffer length less than size of structure!"))
	}
	
    pub fn new_from_bytes(buf: &[u8]) -> Result<Rdata, String> {
        let mut d = Rdata::new();
        let res = d.from_bytes(buf);
        match res {
            Ok(_) => return Ok(d),
            Err(msg) => return Err(msg)
        }
    }
}
//--------------------------------------------------------------------------------------------------------

pub fn test() {
	let a = Rtable {
		characteristics: 0,
		timestamp: 0,
		maj_ver: 6,
		min_ver: 101,
		names: 0,
		ids: 3
	};
	dbg!(&a);
    println!("Test as_bytes: {:?}", a.to_bytes());
}
