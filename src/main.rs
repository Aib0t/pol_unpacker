use hex;
use pe_parser::{pe::parse_portable_executable, section::SectionHeader};
use std::fs;
use std::{path::Path, vec};
fn vec_i8_into_u8(v: Vec<i8>) -> Vec<u8> {
    // ideally we'd use Vec::into_raw_parts, but it's unstable,
    // so we have to do it manually:

    // first, make sure v's destructor doesn't free the data
    // it thinks it owns when it goes out of scope
    let mut v = std::mem::ManuallyDrop::new(v);

    // then, pick apart the existing Vec
    let p = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();

    // finally, adopt the data into a new Vec
    unsafe { Vec::from_raw_parts(p as *mut u8, len, cap) }
}

fn vec_u8_into_i8(v: Vec<u8>) -> Vec<i8> {
    // ideally we'd use Vec::into_raw_parts, but it's unstable,
    // so we have to do it manually:

    // first, make sure v's destructor doesn't free the data
    // it thinks it owns when it goes out of scope
    let mut v = std::mem::ManuallyDrop::new(v);

    // then, pick apart the existing Vec
    let p = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();

    // finally, adopt the data into a new Vec
    unsafe { Vec::from_raw_parts(p as *mut i8, len, cap) }
}

fn main() {
    println!("Hello, world!");
    let (text_section, pol_section) = parse_pol_pe(Path::new("./pol.exe")).unwrap();

    let binary = fs::read(Path::new("./pol.exe")).unwrap();

    let pol_section_data = vec_u8_into_i8(
        binary[pol_section.pointer_to_raw_data as usize
            ..(pol_section.pointer_to_raw_data + pol_section.size_of_raw_data) as usize]
            .to_vec(),
    );

    let mut decoded_text_vec: Vec<i8> = vec![];

    let len = (pol_section.size_of_raw_data - 16) as usize; // ?
    let mut pos: usize = 0;

    while pos < len {
        let mut unk3: u8 = 8;
        let mut unk6 = pol_section_data[pos];
        pos += 1;

        while unk3 != 0 {
            let unk5 = unk6;
            unk6 = unk5 << 1;

            if unk5 < 0 {
                decoded_text_vec.push(pol_section_data[pos]);
                pos += 1;
            } else {
                let unk1 = pol_section_data[pos];
                let temp = [unk1.to_le_bytes(),pol_section_data[1].to_le_bytes()].concat();
                let unk2: i16 = i16::from_le_bytes(temp.try_into().unwrap());

                if unk2 & 0x0fff == 0 {
                    println!("Unk2: {unk2}");
                    return;
                }

                pos += 2;

                let mut unk4 = (unk1 as u8 >> 4) + 3;
                while unk4 != 0 {
                    let unk6_1: i16 = i16::from_le_bytes(
                        [
                            pol_section_data[(unk2 & 0x0fff) as usize].to_le_bytes(),
                            unk6.to_le_bytes(),
                        ]
                        .concat()
                        .try_into()
                        .unwrap(),
                    );
                    decoded_text_vec.push((unk6_1 >> 8) as i8);
                    println!("unk4: {unk4}");
                    unk4 -= 1;
                }
            }
            unk3 -= 1;
        }
        println!(
            "{:?}",
            hex::encode(&vec_i8_into_u8(decoded_text_vec.clone()))
        );
    }
}

fn parse_pol_pe(path: &Path) -> Option<(SectionHeader, SectionHeader)> {
    let binary = fs::read(path).unwrap();
    let pe = parse_portable_executable(binary.as_slice()).unwrap();
    let mut text_section = None;
    let mut pol_section = None;

    for section in pe.section_table {
        let formatted_name = String::from_utf8(section.name.to_vec())
            .unwrap()
            .replace("\0", "");

        if formatted_name == ".text" {
            text_section = Some(section)
        } else if formatted_name == "POL1" {
            pol_section = Some(section)
        }
    }

    return Some((text_section.unwrap(), pol_section.unwrap()));
}
