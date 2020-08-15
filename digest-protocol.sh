grep "^$1 " protocol-and-regex | cut -d " " -f 2- | rev | cut -c 2- | rev | cut -c 3- > protocols/$1
