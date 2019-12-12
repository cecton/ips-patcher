use nom::{
    bytes::complete::{tag, take},
    combinator::{all_consuming, map},
    multi::many_till,
    number::complete::{be_u16, be_u24, be_u8},
    IResult,
};
use std::io::{Seek, SeekFrom, Write};

#[derive(Debug)]
enum Hunk {
    Bytes { address: u64, chunk: Vec<u8> },
    RLE { address: u64, size: usize, byte: u8 },
}

fn header(i: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(b"PATCH")(i)
}

fn eof(i: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(b"EOF")(i)
}

fn address(i: &[u8]) -> IResult<&[u8], u32> {
    be_u24(i)
}

fn num_bytes(i: &[u8]) -> IResult<&[u8], u16> {
    be_u16(i)
}

fn rle(i: &[u8]) -> IResult<&[u8], (u16, u8)> {
    let (i, size) = be_u16(i)?;
    let (i, byte) = be_u8(i)?;

    Ok((i, (size, byte)))
}

fn chunk(i: &[u8], len: u16) -> IResult<&[u8], &[u8]> {
    take(len as usize)(i)
}

fn parse_hunk(i: &[u8]) -> IResult<&[u8], Hunk> {
    let (i, address) = address(i)?;
    let (i, size) = num_bytes(i)?;

    if size > 0 {
        let (i, chunk) = chunk(i, size)?;

        Ok((
            i,
            Hunk::Bytes {
                address: address as u64,
                chunk: chunk.into(),
            },
        ))
    } else {
        let (i, (size, byte)) = rle(i)?;

        Ok((
            i,
            Hunk::RLE {
                address: address as u64,
                size: size as usize,
                byte,
            },
        ))
    }
}

fn parse_ips(i: &[u8]) -> IResult<&[u8], Vec<Hunk>> {
    let (i, _) = header(i)?;

    all_consuming(map(many_till(parse_hunk, eof), |(hunks, _eof)| hunks))(i)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("USAGE: {} <ips_file> <rom_file>", args[0]);
        return Ok(());
    }

    let patch = std::fs::read(args[1].as_str())?;
    let (_, hunks) = parse_ips(patch.as_slice()).expect("could not parse");

    let mut rom = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(args[2].as_str())?;
    let file_size = rom.seek(SeekFrom::End(0))?;
    for hunk in hunks {
        match hunk {
            Hunk::Bytes { address, chunk } => {
                if address > file_size {
                    panic!("Address outside file: {:x} > {:x}", address, file_size);
                }
                rom.seek(SeekFrom::Start(address as u64))?;
                rom.write_all(chunk.as_slice())?;
            }
            Hunk::RLE {
                address,
                size,
                byte,
            } => {
                if address > file_size {
                    panic!("Address outside file: {:x} > {:x}", address, file_size);
                }
                rom.seek(SeekFrom::Start(address as u64))?;
                rom.write_all(
                    std::iter::repeat(byte)
                        .take(size)
                        .collect::<Vec<_>>()
                        .as_slice(),
                )?;
            }
        }
    }

    Ok(())
}
