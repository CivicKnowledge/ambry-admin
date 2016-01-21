Packer build files for Ambry Builder

The Builder is a virtual machine that builds a package, writes the output
files to sorage ( usually S3 ), then terminates, removing the VM.


Building:

You can set your AWS keys in either the `packer build` command line, or
in the environment

Command line: 

    $ packer build \
        -var "aws_access_key=YOUR ACCESS KEY" \
        -var "aws_secret_key=YOUR SECRET KEY" \
        builder.json
        
Environment:
   
    $ export AWS_ACCESS_KEY=... AWS_SECRET_KEY=...
    $ packer build builder.json 
