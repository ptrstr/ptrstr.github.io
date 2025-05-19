+++
title = "NorthSec 2025 Hit the Jackpot Track Writeup"
date = "2025-05-19T10:57:21-04:00"
tags = ["nsec", "writeup", "ctf"]
keywords = ["nsec", "writeup", "ctf", "rng", "reversing", "web"]
description = "Writeup for NorthSec 2025's Hit the Jackpot track (web, reversing and rng)"
cover = "flag-reels.png"
color = "blue"
+++

## Intro

This year at NorthSec, I completed a very interesting track that taught me a lot about Tauri and RNGs in general. The goal: Hit the Jackpot.

## 1/9 [reels] 1/1 That seems like a nice one to hit

When playing the slot machine, we could sometimes peek into one of the icons which was a flag.
{{< image src="flag-reels.png" alt="Flag peeking screenshot" position="center" style="border-radius: 8px;" >}}

Reconstructing all of the images together, we can obtain the flag: `FLAGj65h4j6ZDa5Z6blT`

## 3/9 [web] 1/2 You thought the serial number was enough?

The first flag was obtainable by finding a QR code near the machine at the venue pointing to a website that provided firmware and spec sheets. We could then enter the model number of the machine on the website and find the flag.

{{< image src="flag-model-number.png" alt="Screenshot of spec sheet website" position="center" style="border-radius: 8px;" >}}

## 4/9 [web] 2/2 They really seem to care about their intellectual property…

Unfortunately, the firmware download was protected by a password. However, when submitting passwords, no requests are issued, and looking in the HTML, we find this function:

{{< code language="js" >}}
form.addEventListener("submit", function (e) {
    e.preventDefault();

    const password =
        document.getElementById("password").value;

    if (password === "IHeardThatPassphrasesAreReallySecureAndAlsoBetterIfCustomizedSoThisIsTheServicePasswordToAccessWonderlightFirmwareFiles123$") {
        window.location.href = "https://dl.nsec/slot-machine-66d23e935da38635924c1571ad165c5bd36ffe127eb579ec79e32e5226a1f136.tar.gz";
    } else {
        showError();
    }
});
{{< /code >}}

After downloading and extracting the firmware, two files are present:

- README.md
- slot-machine.AppImage

The README.md looked like this:

{{< code language="md" title="README.md in the download" >}}
# Wonderlight Slot Machine
## Flag
FLAG-0f84e7c4569c26ffa72e21a48162de833ac57eb5bfffdddf9031603fca3792fc

## Controls
SpaceBar - Lever + select button
Up Arrow - Up button
Down Arrow - Down button
B - Insert badge
Shift+B - Toggle badge "insert/remove" badge

## TroubleShooting
You need to install FUSE to run AppImages.

Tested on Ubuntu 24.04.2 LTS

Depending on your setup, the following environment variables could help:
____NV_DISABLE_EXPLICIT_SYNC=1 (for Nvidia GPUs)
LIBGL_ALWAYS_SOFTWARE=1
WEBKIT_DISABLE_COMPOSITING_MODE=1
WEBKIT_DISABLE_DMABUF_RENDERER=1
WAYLAND_DISPLAY= (delete the variable, forces use of Xorg instead of Wayland)

If nothing works, try runninng it on a new Ubuntu VM.
{{< /code >}}

## 5/9 [reverse] 1/2 Such a shame that this compression does not have a header.

Using `7z`, I was unable to extract the AppImage, but looking around on Google I found that providing the option `--appimage-help` yields a menu, which contains an option `--appimage-extract` to dump its contents.

There were many binaries and files in the actual AppImage.
{{< image src="file-listing.png" alt="File listings" position="center" style="border-radius: 8px;" >}}

However, looking for interesting strings like 'jackpot' found that the `shared/bin/slot-machine` (250MB) was the interesting binary.

The size is explained by two things. Firstly, right after opening it, we can see that the symbols were included in the binary. Secondly, after looking at the function names and other information, we can see that the app uses Tauri.

Tauri is a framework that allows building desktop applications in Rust, using a HTML/CSS/JavaScript frontend. It is similar to Electron for the idea, but unfortunately for us, it differs in that the backend language is compiled, and the assets aren't bundled in a nice separate file.

Tauri bundles assets inside the binary itself and compresses them. I didn't really want to go and carve out the asset information, and preliminary attempts of dumping the memory of the `WebKitWebProcess` at runtime and finding the HTML wasn't too convenient.

I opted for an alternative method, and looked at the imports in the binary. A particularly interesting import was `webkit_settings_set_enable_developer_extras`. By looking at the [docs](https://webkitgtk.org/reference/webkit2gtk/2.5.3/WebKitSettings.html#webkit-settings-set-enable-developer-extras), we can see that the function is very simple:

{{< code language="c" >}}
void
webkit_settings_set_enable_developer_extras
                               (WebKitSettings *settings,
                                gboolean enabled);
{{< /code >}}

By writing a simple library to `LD_PRELOAD`, it was possible to enable the 'Inspect element' feature by hooking this function:

{{< code language="rust" title="hook.rs" >}}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn webkit_settings_set_enable_developer_extras(settings: *const c_void, _b: u8) {
    println!("hooked :)");
    let symbol = CString::new("webkit_settings_set_enable_developer_extras").unwrap();
    let ptr = unsafe { dlsym(RTLD_NEXT, symbol.as_ptr()) };

    let ptr = unsafe { mem::transmute::<_, unsafe extern "C" fn(*const c_void, u8)>(ptr) };
    unsafe { ptr(settings, 1) };
}
{{< /code >}}

After that, we could inspect element on the main page and find a flag in the HTML:
{{< image src="flag-html.png" alt="HTML flag" position="center" style="border-radius: 8px;" >}}

## 6/9 [reverse] 2/2 Calling Rust from JS feels illegal.

Looking in the requests tab we could see some interesting endpoints:
{{< image src="network-tab.png" alt="Endpoints in network tab" position="center" style="border-radius: 8px;" >}}

If we look for these endpoints in the list of functions of the binary, it is possible to find all of them.
{{< image src="function-list.png" alt="Function list" position="center" style="border-radius: 8px;" >}}

By copying the request as a `fetch()` call from the requests tab, and replicating the request but with `get_secret_flag` as the method, it was possible to dump it:
{{< image src="flag-secret.png" alt="Secret flag" position="center" style="border-radius: 8px;" >}}

## 2/9 [rng] 1/4 Can we even call that random?

For the first RNG flag, it was pretty simple, and it allowed to discover the structure of each level for the rest of the challenges.

Each level (1 through 4) all implemented a trait which looked something like this:

{{< code language="rust" title="level.rs" >}}
pub trait Level {
    fn new() -> Self; // not valid but point being no arguments
    fn get_metadata(&self) -> Metadata; // metadata for the flag (how many wheels, how much starting money, how much money to win)
    fn get_flag(&self) -> &'static str; // the flag, and no, they were not embedded in the binary
    fn get_byte(&mut self) -> u8; // generates a random byte using the level's rng
    fn tick(&mut self); // probably called by the timer, but wasn't needed for flags
    fn get_debug_info(&self) -> Vec<u8>; // dumps some information about the internal state of the rng
    fn get_payout(&self, symbol: &Symbol) -> u64; // gets payout for a specific symbol. not necessary for flag
}
{{< /code >}}

Furthermore, what is also useful for obtaining the flags is how to predict a symbol for a certain random byte. This was the function that did the conversion:

{{< code language="cpp" title="Symbol lookup decompilation" >}}
__int64 __fastcall sub_6715B1()
{
  char v0; // bh
  _UNKNOWN *retaddr; // [rsp+0h] [rbp+0h]

  *((_BYTE *)&retaddr - 9) = v0;
  *((_BYTE *)&retaddr - 1) = v0;
  if ( *((_BYTE *)&retaddr - 9) >= 0x80u )
  {
    if ( *((char *)&retaddr - 9) < -64 )
    {
      *((_DWORD *)&retaddr - 2) = 1;
    }
    else if ( *((_BYTE *)&retaddr - 9) < 0xC0u || *((_BYTE *)&retaddr - 9) >= 0xDAu )
    {
      if ( *((_BYTE *)&retaddr - 9) < 0xDAu || *((_BYTE *)&retaddr - 9) >= 0xF0u )
      {
        if ( *((_BYTE *)&retaddr - 9) < 0xF0u || *((_BYTE *)&retaddr - 9) >= 0xF9u )
        {
          if ( *((_BYTE *)&retaddr - 9) < 0xF9u || *((_BYTE *)&retaddr - 9) >= 0xFDu )
          {
            if ( *((_BYTE *)&retaddr - 9) < 0xFDu || *((_BYTE *)&retaddr - 9) == 0xFF )
            {
              if ( *((_BYTE *)&retaddr - 9) != 0xFF )
                BUG();
              *((_DWORD *)&retaddr - 2) = 7;
            }
            else
            {
              *((_DWORD *)&retaddr - 2) = 6;
            }
          }
          else
          {
            *((_DWORD *)&retaddr - 2) = 5;
          }
        }
        else
        {
          *((_DWORD *)&retaddr - 2) = 4;
        }
      }
      else
      {
        *((_DWORD *)&retaddr - 2) = 3;
      }
    }
    else
    {
      *((_DWORD *)&retaddr - 2) = 2;
    }
  }
  else
  {
    *((_DWORD *)&retaddr - 2) = 0;
  }
  return *((unsigned int *)&retaddr - 2);
}
{{< /code >}}

Cleaning it up a little, we can get this:

{{< code language="rust" title="symbol.rs" >}}
#[repr(u8)]
#[derive(PartialEq, Eq, Debug)]
pub enum Symbol {
    Cherry,
    Bar,
    DoubleBar,
    TripleBar,
    Seven,
    MinorJackpot,
    MajorJackpot,
    GrandJackpot,
}

impl Symbol {
    pub fn from_rng_number(number: u8) -> Symbol {
        match number {
            0x00..=0x7F => Symbol::Cherry,
            0x80..=0xBF => Symbol::Bar,
            0xC0..=0xD9 => Symbol::DoubleBar,
            0xDA..=0xEF => Symbol::TripleBar,
            0xF0..=0xF8 => Symbol::Seven,
            0xF9..=0xFC => Symbol::MinorJackpot,
            0xFD..=0xFE => Symbol::MajorJackpot,
            0xFF        => Symbol::GrandJackpot,
        }
    }
}
{{< /code >}}

What is really useful are the `new()` and `get_byte()` methods, as they are the ones modifying the state of the RNG, and we can use them to predict it too.

For the first level, those methods are quite simple:

{{< code language="cpp" title="Level 1 decompilation" >}}
slot_machine_lib::rngs::level1::Level1Rng *__cdecl slot_machine_lib::rngs::level1::Level1Rng::new(
        slot_machine_lib::rngs::level1::Level1Rng *__return_ptr retstr)
{
  rand::rngs::std::StdRng v2; // [rsp+10h] [rbp-148h] BYREF

  rand_core::SeedableRng::seed_from_u64(&v2, 0LL);
  memcpy(retstr, &v2, sizeof(slot_machine_lib::rngs::level1::Level1Rng));
  return retstr;
}

u8 __cdecl <slot_machine_lib::rngs::level1::Level1Rng as slot_machine_lib::rngs::SlotRng>::get_byte(
        slot_machine_lib::rngs::level1::Level1Rng *self)
{
  return rand::rng::Rng::random(&self->rng);
}
{{< /code >}}

Reimplementing it in Rust, we get this:

{{< code language="rust" title="Level 1 solution" >}}
fn level1() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    for i in 0..30 {
        let spin = (0..3).map(|_| Symbol::from_rng_number(rng.random::<u8>())).collect::<Vec<_>>();

        if spin[0] == spin[1] && spin[1] == spin[2] {
            println!("spin {}: {:?}", i, spin[0]);
        }
    }
}
{{< /code >}}

With the following output:

```
spin 3: Cherry
spin 7: Cherry
spin 10: Bar
spin 11: Cherry
spin 18: Cherry
spin 19: Cherry
```

{{< video src="flag-rng-level1" >}}

## 7/9 [rng] 2/4 The most classic RNG attack in the book.

The next flag was very similar but with the added difficulty of relying on time.

The RNG functions look like this:

{{< code language="cpp" title="Level 2 decompilation" >}}
slot_machine_lib::rngs::level2::Level2Rng *__cdecl slot_machine_lib::rngs::level2::Level2Rng::new(
        slot_machine_lib::rngs::level2::Level2Rng *__return_ptr retstr,
        slot_machine_lib::clock::Clock *clock)
{
  slot_machine_lib::rngs::level2::Level2Rng *result; // rax
  u64 v3; // [rsp+10h] [rbp-188h]
  core::sync::atomic::AtomicU64 *v4; // [rsp+30h] [rbp-168h]
  flume::Receiver<std::time::SystemTime> *v5; // [rsp+38h] [rbp-160h]
  rand::rngs::std::StdRng v6; // [rsp+40h] [rbp-158h] BYREF
  slot_machine_lib::clock::Clock *v7; // [rsp+180h] [rbp-18h]

  v7 = clock;
  v5 = slot_machine_lib::clock::Clock::subscribe((flume::Receiver<std::time::SystemTime> *)clock, clock);
  v4 = <alloc::sync::Arc<T,A> as core::ops::deref::Deref>::deref((alloc::sync::Arc<core::sync::atomic::AtomicU64,alloc::alloc::Global> *)clock);
  v3 = core::sync::atomic::AtomicU64::load(v4, core::sync::atomic::Ordering::Relaxed);
  rand_core::SeedableRng::seed_from_u64(&v6, v3);
  memcpy(retstr, &v6, 0x140uLL);
  result = retstr;
  retstr->clock_receiver.shared.ptr.pointer = (alloc::sync::ArcInner<flume::Shared<std::time::SystemTime>> *)v5;
  return result;
}

u8 __cdecl <slot_machine_lib::rngs::level2::Level2Rng as slot_machine_lib::rngs::SlotRng>::get_byte(
        slot_machine_lib::rngs::level2::Level2Rng *self)
{
  core::result::Result<std::time::SystemTime,flume::TryRecvError> v2; // [rsp+10h] [rbp-18h] BYREF
  slot_machine_lib::rngs::level2::Level2Rng *v3; // [rsp+20h] [rbp-8h]

  v3 = self;
  while ( 1 )
  {
    flume::Receiver<T>::try_recv(&v2, &self->clock_receiver);
    if ( *(_DWORD *)&v2.gap0[8] == 1000000000 )
      break;
    rand::rng::Rng::random(&self->rng);
  }
  return rand::rng::Rng::random(&self->rng);
}
{{< /code >}}

This RNG relies on the current time since UNIX epoch for its seed, but when it generates the next byte, it also takes time into account.

When looking at `try_recv` in `flume`'s documentation, we can see that it will emit an error if the sender has no more messages to send or is empty. We can assume that the code does something like this:

{{< code language="c" title="RNG behaviour approximation" >}}
while (!timerEventReceiver.empty()) {
    timerEventReceiver.recv();
    random();
}

return random();
{{< /code >}}

This means that if we start the challenge at 10:00:00, and spin at 10:00:05, `random()` will have been called 8 times. 5 times to the waste because of each event, and 3 times for the actual spin.

I was able to validate this hypothesis using `ilhook` and hooking into the function to count the number of times it was being called.

{{< code language="log" title="Number of calls for level 2's RNG" >}}
2025-05-19T16:11:00.304699Z  INFO slot_machine_lib: Start level: 2
seed_from_u64: 1747671060
l2: get_byte
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2: get_byte
l2 gen rand
l2: get_byte
l2 gen rand
2025-05-19T16:11:05.103847Z  INFO slot_machine_lib: Spin. New balance: 980, reels: SpinResponse { stops: [Cherry, Bar, Bar], payout: 0, credits: 980 }
l2: get_byte
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2 gen rand
l2: get_byte
l2 gen rand
l2: get_byte
l2 gen rand
2025-05-19T16:11:15.306010Z  INFO slot_machine_lib: Spin. New balance: 960, reels: SpinResponse { stops: [Bar, Cherry, Cherry], payout: 0, credits: 960 }
{{< /code >}}

To predict this algorithm it was a simple loop and keeping track of how many times we jackpotted so that we know how many random calls have been made.

{{< code language="rust" title="Level 2 solution" >}}

fn get_time() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn level2(seed: u64) {
    let start = DateTime::from_timestamp(seed as i64, 0).unwrap().naive_local();
    println!("start {}", start.format("%H:%M:%S"));

    let mut pwns = 0;
    let mut sleep = 10;

    for i in 0..600 {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        for _ in 0..(i + pwns * 3) {
            Symbol::from_rng_number(rng.random::<u8>());
        }

        if sleep > 0 {
            sleep -= 1;
            continue;
        }

        let vect = vec![Symbol::from_rng_number(rng.random::<u8>()), Symbol::from_rng_number(rng.random::<u8>()), Symbol::from_rng_number(rng.random::<u8>())];
        if vect[0] == vect[1] && vect[1] == vect[2] {
            let x = DateTime::from_timestamp((seed + i) as i64, 0).unwrap().naive_local();
            
            println!("  {}: {:?}", x.format("%H:%M:%S"), vect);

            pwns += 1;

            sleep = 10;
        }
    }

    return;
}

fn main() {
    level2(get_time());
}
{{< /code >}}

{{< video src="flag-rng-level2" >}}

## 8/9 [rng] 3/4 That debug screen felt pretty phishy, didn't it?

When opening the third level, a new screen appears, showing "debug" information:
{{< image src="debug-information.png" alt="Screenshot of debug information" position="center" style="border-radius: 8px;" >}}

Looking at the code, these are the functions, along with `get_debug_info`:

{{< code language="cpp" title="Level 3 decompilation" >}}
slot_machine_lib::rngs::level3::Level3Rng *__cdecl slot_machine_lib::rngs::level3::Level3Rng::new(
        slot_machine_lib::rngs::level3::Level3Rng *__return_ptr retstr)
{
  slot_machine_lib::rngs::level3::mt19937::Mt19937Rng v2; // [rsp+10h] [rbp-9C8h] BYREF

  rand_core::SeedableRng::from_os_rng(&v2);
  memcpy(retstr, &v2, sizeof(slot_machine_lib::rngs::level3::Level3Rng));
  return retstr;
}

u8 __cdecl <slot_machine_lib::rngs::level3::Level3Rng as slot_machine_lib::rngs::SlotRng>::get_byte(
        slot_machine_lib::rngs::level3::Level3Rng *self)
{
  return rand::rng::Rng::random(&self->rng);
}

core::option::Option<alloc::vec::Vec<u8,alloc::alloc::Global>> *__cdecl <slot_machine_lib::rngs::level3::Level3Rng as slot_machine_lib::rngs::SlotRng>::get_debug_info(
        core::option::Option<alloc::vec::Vec<u8,alloc::alloc::Global>> *__return_ptr retstr,
        slot_machine_lib::rngs::level3::Level3Rng *self)
{
  _mut__u8_ v2; // rax
  core::option::Option<alloc::vec::Vec<u8,alloc::alloc::Global>> *result; // rax
  alloc::vec::Vec<u8,alloc::alloc::Global> v4; // [rsp+40h] [rbp-48h] BYREF
  alloc::vec::Vec<u8,alloc::alloc::Global> v5; // [rsp+58h] [rbp-30h]
  slot_machine_lib::rngs::level3::Level3Rng *v6; // [rsp+70h] [rbp-18h]

  v6 = self;
  if ( !is_mul_ok(4uLL, 0x320uLL) )
    core::panicking::panic_const::panic_const_mul_overflow();
  alloc::vec::from_elem(&v4, 0, 3200uLL);
  v2 = <alloc::vec::Vec<T,A> as core::ops::deref::DerefMut>::deref_mut(&v4);
  <slot_machine_lib::rngs::level3::mt19937::Mt19937Rng as rand_core::RngCore>::fill_bytes(&self->rng, v2);
  result = retstr;
  v5 = v4;
  *(_QWORD *)retstr->gap0 = v4.buf.inner.cap.__0;
  *(_OWORD *)&retstr->gap0[8] = *(_OWORD *)&v5.buf.inner.ptr.pointer.pointer;
  return result;
}
{{< /code >}}

Without going too much down the chain of functions, the `new()` function will use a standard Mersenne Twister RNG using a 16 byte random key, provided by the system's CSPRNG.

However, Googling for mt19937 reversing landed me on [this repository](https://github.com/twisteroidambassador/mt19937-reversible/) containing a simple Python implementation.

By modifying `MT19937`'s `w` parameter (key size) to 128 instead of 32, and using OCR to dump the data, it was possible to feed the data in their algorithm and recover the seed.

{{< code language="python" title="Level 3 solution" >}}
from enum import Enum

class Symbol(Enum):
    Cherry = 1
    Bar = 2
    DoubleBar = 3
    TripleBar = 4
    S4 = 5
    S5 = 6
    S6 = 7
    Flag = 8

    @staticmethod
    def from_rng_number(number: int) -> 'Symbol':
        if 0x00 <= number <= 0x7F:
            return Symbol.Cherry
        elif 0x80 <= number <= 0xBF:
            return Symbol.Bar
        elif 0xC0 <= number <= 0xD9:
            return Symbol.DoubleBar
        elif 0xDA <= number <= 0xEF:
            return Symbol.TripleBar
        elif 0xF0 <= number <= 0xF8:
            return Symbol.S4
        elif 0xF9 <= number <= 0xFC:
            return Symbol.S5
        elif 0xFD <= number <= 0xFE:
            return Symbol.S6
        elif number == 0xFF:
            return Symbol.Flag
        else:
            raise ValueError(f"Invalid RNG number: {number}")

a = '''
617b700d597a2952a6e0757ba63a94c086849fe4a55ff908cc18fa8b0f23edf 1a59b3c4dddb48e578eaf11c5acbb4f75f6a471d8654f995583714cd61aa469 ee336821f88d452a0fa32c964b53029f8d4226e2a290b2604ffc9e364a8422b aa48be92ffca9ebec9eeb010d3d3f3c6da59948a819c8c3084dec4410a1877a 03a37d79c1f18ef06a6bc71da75b2acb4a3c96944cd2b405f2beb4f03c000ea fbea56e56e99e8d54aa45c6055ede26c7c61f57df20ffd83532c86e4b194dbe d9b50f0f1c22810db3a93d3f77c6ec4bc6ccbf8f3a8b0186013782a762d4891 4dc67e46a5b1902e3f2f578fe8618d76ad6e10700607e14f9d5d1972c189e1f 6908141e50e49e3480e5d9f887c35e6eab04f52add54f0a01d3b52623f85eac e4b004c0626343ddf489ba714a59827c088a93091a369ac40dbac959755f5ce

... other input data
'''
import struct

# simple error detection
a = a.lower().replace('\n', '').replace(' ', '').replace('o','0').replace('.', '').replace('@', '8')

a = [a[i:i+8] for i in range(0, len(a), 8)]
a = [struct.unpack('<I', bytes.fromhex(i))[0] for i in a[:-1]]
print(len(a))

mt = MT19937()
print(mt.n)
mt.clone_state_from_output(a[:mt.n])
for _ in range(800 - mt.n): # the debug dump is 3200 bytes, so 800 random 4 byte values
    mt.get_next_random().to_bytes(4, byteorder='big').hex()

for i in range(30):
    ff0 = Symbol.from_rng_number(mt.get_next_random() & 0xff)
    ff1 = Symbol.from_rng_number(mt.get_next_random() & 0xff)
    ff2 = Symbol.from_rng_number(mt.get_next_random() & 0xff)

    if ff0 == ff1 and ff1 == ff2:
        print(f'{i}: {ff0}')
{{< /code >}}

*Note: To save time for the PoC I just copy pasted, but you can use your phone and OCR as well.*
{{< video src="flag-rng-level3" >}}

## 9/9 [rng] 4/4 Not having the actual byte value really makes it harder.

For the last flag, it was a similar situation to the 3rd RNG, where a public algorithm was used.

The code looks like this:

{{< code language="cpp" title="Level 4 decompilation" >}}
struct slot_machine_lib::rngs::level4::simple_lfsr::SimpleLfsr {
    u64 data;
    usize size;
};

slot_machine_lib::rngs::level4::Level4Rng __cdecl slot_machine_lib::rngs::level4::Level4Rng::new()
{
  slot_machine_lib::rngs::level4::Level4Rng result; // rax

  result.rng = rand_core::SeedableRng::from_os_rng();
  return result;
}

u8 __cdecl <slot_machine_lib::rngs::level4::Level4Rng as slot_machine_lib::rngs::SlotRng>::get_byte(
        slot_machine_lib::rngs::level4::Level4Rng *self)
{
  return rand::rng::Rng::random(&self->rng);
}

slot_machine_lib::rngs::level4::simple_lfsr::SimpleLfsr *__cdecl <slot_machine_lib::rngs::level4::simple_lfsr::SimpleLfsr as rand_core::SeedableRng>::from_seed(
        slot_machine_lib::rngs::level4::simple_lfsr::SimpleLfsr *__return_ptr retstr,
        u8 seed[8])
{
  return (slot_machine_lib::rngs::level4::simple_lfsr::SimpleLfsr *)core::num::<impl u64>::from_ne_bytes((u8 *)retstr);
}

u32 __cdecl <slot_machine_lib::rngs::level4::simple_lfsr::SimpleLfsr as rand_core::RngCore>::next_u32(
        slot_machine_lib::rngs::level4::simple_lfsr::SimpleLfsr *self)
{
  usize v1; // rax
  u64 v2; // rax
  usize v4; // [rsp+8h] [rbp-30h]
  usize v5; // [rsp+18h] [rbp-20h]

  if ( self->size >= 5 )
  {
    self->size = 0LL;
    self->data ^= self->data << 10;
    self->data &= 0xFFFFFFFFFFuLL;
    self->data ^= self->data >> 26;
    self->data &= 0xFFFFFFFFFFuLL;
  }
  v5 = 8 * self->size;
  if ( !is_mul_ok(8uLL, self->size) )
    core::panicking::panic_const::panic_const_mul_overflow();
  if ( v5 >= 0x40 )
    core::panicking::panic_const::panic_const_shr_overflow();
  v1 = self->size;
  v4 = v1 + 1;
  if ( v1 == -1LL )
    core::panicking::panic_const::panic_const_add_overflow();
  v2 = (self->data ^ 0xF267BCB3B2LL) >> (v5 & 0x3F);
  self->size = v4;
  return v2;
}
{{< /code >}}

Looking around online, I couldn't find any information about reversing the algorithm. Also, by hooking the `next_u32` function, I saw that for every `get_byte`, one `next_u32` was called. Interestingly, this algorithm only slides bytes to the right on each iteration. However, the difficulty of this challenge was mainly because we couldn't see the actual data, and could only see the spins.

This pushed me to use [z3](https://github.com/Z3Prover/z3), as I could already see that we'd have to rely on constraints.

By reversing the algorithm, I came up with this script:

{{< code language="python" title="Level 4 solver" >}}
from z3 import *
from enum import Enum

solver = Solver()


class Symbol(Enum):
    Cherry = 1
    Bar = 2
    DoubleBar = 3
    TripleBar = 4
    Seven = 5
    MinorJackpot = 6
    MajorJackpot = 7
    GrandJackpot = 8

    @staticmethod
    def from_rng_number(number: int) -> "Symbol":
        if 0x00 <= number <= 0x7F:
            return Symbol.Cherry
        elif 0x80 <= number <= 0xBF:
            return Symbol.Bar
        elif 0xC0 <= number <= 0xD9:
            return Symbol.DoubleBar
        elif 0xDA <= number <= 0xEF:
            return Symbol.TripleBar
        elif 0xF0 <= number <= 0xF8:
            return Symbol.Seven
        elif 0xF9 <= number <= 0xFC:
            return Symbol.MinorJackpot
        elif 0xFD <= number <= 0xFE:
            return Symbol.MajorJackpot
        elif number == 0xFF:
            return Symbol.GrandJackpot

    @staticmethod
    def range(number: Symbol):
        return {
            Symbol.Cherry: [0x00, 0x7F],
            Symbol.Bar: [0x80, 0xBF],
            Symbol.DoubleBar: [0xC0, 0xD9],
            Symbol.TripleBar: [0xDA, 0xEF],
            Symbol.Seven: [0xF0, 0xF8],
            Symbol.MinorJackpot: [0xF9, 0xFC],
            Symbol.MajorJackpot: [0xFD, 0xFE],
            Symbol.GrandJackpot: [0xFF, 0xFF],
        }[number]


class Ctx:
    def __init__(self, data):
        self.data = data & 0xFFFFFFFFFF
        self.size = 0

    def forward(self):
        if self.size >= 5:
            self.size = 0
            self.data ^= self.data << 10
            self.data &= 0xFFFFFFFFFF
            self.data ^= self.data >> 26
            self.data &= 0xFFFFFFFFFF

        v5 = 8 * self.size
        shift = v5 & 0x3F
        ret = (self.data ^ 0xF267BCB3B2) >> shift
        self.size += 1
        return ret & 0xFF


obtained = [
    Symbol.Cherry,
]

seeds = [BitVec("seed", 64)]
mask = BitVecVal(0xFFFFFFFFFF, 64)
xor_const = BitVecVal(0xF267BCB3B2, 64)
for i, o in enumerate(obtained):
    rng = Symbol.range(o)
    size = i % 5
    generation = i // 5

    if len(seeds) <= generation:
        prev = seeds[-1]
        tmp = prev ^ (prev << 10)
        tmp = tmp & mask
        tmp = tmp ^ LShR(tmp, 26)
        tmp = tmp & mask
        seeds.append(tmp)

    v5 = size * 8
    shift = v5 & 0x3F
    masked_data = seeds[-1] & mask
    xored = masked_data ^ xor_const
    ret = LShR(xored, shift)
    ret_byte = Extract(7, 0, ret)

    solver.add(ret_byte >= rng[0], ret_byte <= rng[1])

print(solver.check())
print(solver.model())

print("found")

print(solver.model()[seeds[0]].as_long())
ctx = Ctx(solver.model()[seeds[0]].as_long())

for _ in range(len(obtained)):
    ctx.forward()

for i in range(100):
    ff = [ctx.forward(), ctx.forward(), ctx.forward()]
    ff = [Symbol.from_rng_number(x) for x in ff]
    if ff[0] == ff[1] and ff[1] == ff[2]:
        print(i, ff[0])
    else:
        print(ff)
{{< /code >}}

{{< video src="flag-rng-level4" >}}

The NorthSec team also captured a video of myself completing this last challenge:
{{< video src="flag-rng-level4-irl" >}}

## Closing

This was a super fun and interesting track. It was a great oppotunity to learn how Tauri worked, and a bit more on `z3` too.

I'm excited to see what they'll come up with next year :)

Thanks for reading through this!
