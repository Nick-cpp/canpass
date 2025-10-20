If you use Arch by the way you can get this from AUR ( yay -S canpass )

Installation guide

step 1: installing needed packages


$ sudo apt install gcc git  --  debian/debian-based

$ sudo pacman -S gcc git  --  arch/arch-based


step 2: download the project repository


$ git clone https://github.com/Nick-cpp/canpass


step 3: compilaton and instalation


$ cd canpass/

$ g++ -std=c++17 "canpass.cpp" -o canpass

$ sudo install -Dm755 canpass "$pkgdir/usr/bin/canpass"
