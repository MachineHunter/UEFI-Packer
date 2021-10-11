if ($args.Count -lt 2) {
	echo "./custome-packer.exe <file-to-pack> <output-file>"
}
else {
	..\custom-packer\x64\Debug\custom-packer.exe $args[0] $args[1]
}
