# Theoretical Processor module for IDA Pro 7.7 and 8.3


## Features

* Analysis of the known instruction set
* Memory map cfg for ROM and RAM 
* Basic data/code reference detection, manual address support too
* Branch detection


## Building

[Windows]

[GUI]
1) Install Visual Studio 2022.
2) Unpack the IDA SDK to a directory on your computer.
3) Clone this repository into the IDA SDK `module` directory.
4) Open the `kirk.sln` solution in Visual Studio and build.
5) Proc modules will be copied into the users %APPDATA\Hex-Rays\IDA Pro\procs folder
6) Copy the `cfg\kirk.cfg` file to your `%APPDATA\Hex-Rays\IDA Pro\cfg` folder and update the definitions as appropriate for your implementation.

[makefile]
1) Configure the `$IDASDK` environment variable.
2) Clone this repository into the `$IDASDK/module` directory.
3) Edit the `$IDASDK/module/makefile` and add the repository directory to `DIRS32`.
4) Follow the IDA SDK build instructions.

## License

The code is licensed under [MIT License](LICENSE) 
