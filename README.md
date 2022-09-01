# bye
Command line tool for file encryption

Bye, once installed on your machine, will encrypt files for you as quickly as you can type "bye encrypt hello.txt", a passkey, and a hint. 

To install, clone this repo, and run "go build" and then "go install" from the bye directory. For more detailed instructions, and how to get
the Go install directory on your system's shell path, see: https://go.dev/doc/tutorial/compile-install

Once it's installed, "bye encrypt hello.txt" will encrypt hello.txt, deleting the orignal file. In its place, you'll find hello.txt.bye, which
will be full of gibberish. To make sense of it, run "bye decrypt hello.txt.bye" and enter the original passkey when prompted. 

NOTE: bye works by creating a second, hidden metadata file with a filename identical to the first, except that it begins with a dot. So, encrypting "hello.txt" deletes the original file and creates two new ones: "hello.txt.bye" and ".hello.txt.bye" This is all well and good on *nix, but won't work 
at all on Windows. Sorry! Also, be careful not to move the encrypted file without moving the metadata file as well, or decryption won't be possible 
until they're reunited.
