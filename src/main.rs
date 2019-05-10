extern crate byteorder;
extern crate hexdump;

use std::io;
use std::io::{Error, ErrorKind};
use std::str;
use std::io::prelude::*;
use std::fs::File;
use std::io::SeekFrom;
use byteorder::{ByteOrder, LittleEndian};
use hexdump::hexdump;

fn main() -> io::Result<()> {
    let mut msdos_buf = [0u8;64];
    let mut pe_buf = vec![0u8;256];

    let mut f = File::open("samples/twain_32.dll")?;
    f.read_exact(&mut msdos_buf)?;
    let mz = LittleEndian::read_u16(&msdos_buf[..2]);
    if mz != 0x5A4D {
        println!("MZ signature not found!");
        println!("MZ: 0x0{:X?}", mz);
        return Err(Error::new(ErrorKind::Other, "MZ Signature not valid"))
    }
    //--------------------------------------------------------
    
    let pe_ofs = LittleEndian::read_u32(&msdos_buf[60..]);
    //println!("PE offset: 0x0{:X?}", pe_ofs);
    f.seek(SeekFrom::Start(pe_ofs as u64))?;
    f.read_exact(&mut pe_buf[0..248])?;
    let pe = LittleEndian::read_u32(&pe_buf[..4]);
    if pe != 0x4550 {
        println!("PE signature not found!");
        println!("PE: 0x0{:X?}", pe);
        return Err(Error::new(ErrorKind::Other, "PE Signature not valid"))
    }
    //--------------------------------------------------------

    let magic = LittleEndian::read_u16(&pe_buf[24..26]);
    println!("Magic                 : 0x{:X?}", magic);
    let machine = LittleEndian::read_u16(&pe_buf[4..6]);
    println!("Machine type          : 0x{:X?}", machine);
    let nr_sections = LittleEndian::read_u16(&pe_buf[6..8]);
    println!("Number of sections    : {}", nr_sections);
    if nr_sections == 0 || nr_sections > 128 {
        println!("Invalid number of sections!");
        return Err(Error::new(ErrorKind::Other, "Invalid number of sections"))
    }
    //--------------------------------------------------------

    let imagebase: u64;
    let nr_dirs: u32;
    let di;     // directory index in PE header
    match magic {
        0x10B => {
            imagebase = LittleEndian::read_u32(&pe_buf[52..56]) as u64;
            nr_dirs = LittleEndian::read_u32(&pe_buf[116..120]);
            di = 96 + 24;
        },
        0x20B => {
            imagebase = LittleEndian::read_u64(&pe_buf[48..56]);
            nr_dirs = LittleEndian::read_u32(&pe_buf[132..136]);
            di = 112 + 24;
        },
        _ => {
            println!("Unknown PE type!");
            return Err(Error::new(ErrorKind::Other, "Unknown PE type"))
        }
    }
    println!("Image base address    : 0x{:X?}", imagebase);
    println!("Number of directories : {}", nr_dirs);

    let section_align = LittleEndian::read_u32(&pe_buf[56..60]);
    println!("Section mem alignment : 0x{:X?} ({} bytes)", section_align, section_align);

    let file_align = LittleEndian::read_u32(&pe_buf[60..64]);
    println!("File alignment        : 0x{:X?} ({} bytes)", file_align, file_align);

    let headers_size = LittleEndian::read_u32(&pe_buf[84..88]);
    println!("Size of headers       : 0x{:X?} ({} bytes)", headers_size, headers_size);
    //--------------------------------------------------------

    f.seek(SeekFrom::Start(pe_ofs as u64))?;
    pe_buf = vec![0u8;(headers_size-64) as usize];
    f.read_exact(&mut pe_buf)?;
    //--------------------------------------------------------

    if nr_dirs >= 3 {
        let dir_rsrc_rva = LittleEndian::read_u32(&mut pe_buf[di+8*2..di+8*2+4]);  
        let dir_rsrc_siz = LittleEndian::read_u32(&mut pe_buf[di+8*2+4..di+8*2+8]);  
        println!("Resource directory    : rva 0x{:X?}, virtual size {} bytes", dir_rsrc_rva, dir_rsrc_siz);

        let si: usize = di + (nr_dirs as usize)*8;        // Section table index in PE header
        let mut sec_rsrc_ofs = 0;
        let mut sec_rsrc_psize = 0;
        for i in 0..nr_sections as usize {
            let rva = LittleEndian::read_u32(&pe_buf[si+i*40+12..si+i*40+12+4]);
            let vsize = LittleEndian::read_u32(&pe_buf[si+i*40+8..si+i*40+8+4]);
            if rva == dir_rsrc_rva && vsize == dir_rsrc_siz {
                sec_rsrc_ofs += LittleEndian::read_u32(&pe_buf[si+i*40+20..si+i*40+20+4]);
                sec_rsrc_psize += LittleEndian::read_u32(&pe_buf[si+i*40+16..si+i*40+16+4]);
                print!("Resource section name : [{}]", str::from_utf8(&mut pe_buf[si+i*40..si+i*40+8]).unwrap());
                println!(" offset {:X?}, size {} bytes", sec_rsrc_ofs, sec_rsrc_psize);
                break;
            }
        }
        if sec_rsrc_ofs == 0 {
            println!("Invalid resource section file offset");
            return Err(Error::new(ErrorKind::Other, "Resource section not found"))
        }

        f.seek(SeekFrom::Start(sec_rsrc_ofs as u64))?;
        let mut rsrc_section = vec![0u8; sec_rsrc_psize as usize];
        f.read_exact(&mut rsrc_section)?;

        hexdump(&rsrc_section[0..128]);

        let mut ti: usize = 0;

        let mut t_characteristics = LittleEndian::read_u32(&rsrc_section[ti..ti+4]);
        let mut t_timestamp = LittleEndian::read_u32(&rsrc_section[ti+4..ti+8]);
        let mut t_majorv = LittleEndian::read_u16(&rsrc_section[ti+8..ti+10]);
        let mut t_minorv = LittleEndian::read_u16(&rsrc_section[ti+10..ti+12]);
        let mut t_nr_of_names = LittleEndian::read_u16(&rsrc_section[ti+12..ti+14]);
        let mut t_nr_of_ids = LittleEndian::read_u16(&rsrc_section[ti+14..ti+16]);

        println!("Characteristics: 0x{:X?}", t_characteristics);
        println!("Timestamp: 0x{:X?}", t_timestamp);
        println!("Major Version: {}", t_majorv);
        println!("Minor Version: {}", t_minorv);
        println!("Number of name entries: {}", t_nr_of_names);
        println!("Number of id entries: {}", t_nr_of_ids);

        let mut ni: usize = ti + 16;
        for i in 0..t_nr_of_names as usize {
            let e_name_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8..ni+i*8+4]);
            let e_next_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8+4..ni+i*8+8]);
            println!("  Name offset: 0x{:X?}", e_name_ofs);
            println!("  Item offset: 0x{:X?}", e_next_ofs);
        }

        ni += 8 * t_nr_of_names as usize;
        for i in 0..t_nr_of_ids as usize {
            let e_name_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8..ni+i*8+4]);
            let e_next_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8+4..ni+i*8+8]);
            println!("  ID: 0x{:X?}", e_name_ofs);
            println!("  Item offset: 0x{:X?}", e_next_ofs);
        }




        ti += 16 + 8*t_nr_of_names as usize + 8*t_nr_of_ids as usize;

        t_characteristics = LittleEndian::read_u32(&rsrc_section[ti..ti+4]);
        t_timestamp = LittleEndian::read_u32(&rsrc_section[ti+4..ti+8]);
        t_majorv = LittleEndian::read_u16(&rsrc_section[ti+8..ti+10]);
        t_minorv = LittleEndian::read_u16(&rsrc_section[ti+10..ti+12]);
        t_nr_of_names = LittleEndian::read_u16(&rsrc_section[ti+12..ti+14]);
        t_nr_of_ids = LittleEndian::read_u16(&rsrc_section[ti+14..ti+16]);

        println!("Characteristics: 0x{:X?}", t_characteristics);
        println!("Timestamp: 0x{:X?}", t_timestamp);
        println!("Major Version: {}", t_majorv);
        println!("Minor Version: {}", t_minorv);
        println!("Number of name entries: {}", t_nr_of_names);
        println!("Number of id entries: {}", t_nr_of_ids);

        ni = ti + 16;
        for i in 0..t_nr_of_names as usize {
            let e_name_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8..ni+i*8+4]);
            let e_next_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8+4..ni+i*8+8]);
            println!("  Name offset: 0x{:X?}", e_name_ofs);
            println!("  Item offset: 0x{:X?}", e_next_ofs);
        }

        ni += 8 * t_nr_of_names as usize;
        for i in 0..t_nr_of_ids as usize {
            let e_name_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8..ni+i*8+4]);
            let e_next_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8+4..ni+i*8+8]);
            println!("  ID: 0x{:X?}", e_name_ofs);
            println!("  Item offset: 0x{:X?}", e_next_ofs);
        }




        ti += 16 + 8*t_nr_of_names as usize + 8*t_nr_of_ids as usize;

        t_characteristics = LittleEndian::read_u32(&rsrc_section[ti..ti+4]);
        t_timestamp = LittleEndian::read_u32(&rsrc_section[ti+4..ti+8]);
        t_majorv = LittleEndian::read_u16(&rsrc_section[ti+8..ti+10]);
        t_minorv = LittleEndian::read_u16(&rsrc_section[ti+10..ti+12]);
        t_nr_of_names = LittleEndian::read_u16(&rsrc_section[ti+12..ti+14]);
        t_nr_of_ids = LittleEndian::read_u16(&rsrc_section[ti+14..ti+16]);

        println!("Characteristics: 0x{:X?}", t_characteristics);
        println!("Timestamp: 0x{:X?}", t_timestamp);
        println!("Major Version: {}", t_majorv);
        println!("Minor Version: {}", t_minorv);
        println!("Number of name entries: {}", t_nr_of_names);
        println!("Number of id entries: {}", t_nr_of_ids);

        ni = ti + 16;
        for i in 0..t_nr_of_names as usize {
            let e_name_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8..ni+i*8+4]);
            let e_next_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8+4..ni+i*8+8]);
            println!("  Name offset: 0x{:X?}", e_name_ofs);
            println!("  Item offset: 0x{:X?}", e_next_ofs);
        }

        ni += 8 * t_nr_of_names as usize;
        for i in 0..t_nr_of_ids as usize {
            let e_name_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8..ni+i*8+4]);
            let e_next_ofs = LittleEndian::read_u32(&rsrc_section[ni+i*8+4..ni+i*8+8]);
            println!("  ID: 0x{:X?}", e_name_ofs);
            println!("  Item offset: 0x{:X?}", e_next_ofs);
        }









    } else {
        println!("Here we have to handle the case where there is no resource section");
    }

    Ok(())
}

