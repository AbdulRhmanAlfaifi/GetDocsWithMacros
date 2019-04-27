# GetDocsWithMacros
A python script that takes a path as input then go recursively looking for office file that contains macros.
# Installing dependencies
`pip install -r requirements.txt`
# Simple usage
With no option the script will start looking for office documents with macros starting from C:\ if windows or from / if linux.
# Options
```
usage: getDocsWithMacros.py [-h] [-sd STARTINGDIRECTORY] [-c] [-o OUTPUTFILE]
                            [-ha {md5,sha1}] [-x] [-m]

Collect all doc File that has macros.

optional arguments:
  -h, --help            show this help message and exit
  -sd STARTINGDIRECTORY, --StartingDirectory STARTINGDIRECTORY
                        The starting directory from where the script will
                        start searching. Default is C:\ for windows or / for
                        linux
  -c, --copy            Copy the detected doc files to [CurrentDir]/DOCs.
  -o OUTPUTFILE, --output OUTPUTFILE
                        Output the results to the spicified file with CSV
                        formate.
  -ha {md5,sha1}, --hash {md5,sha1}
                        Which hashing algorithm to use (MD5 or SHA1) default
                        is md5.
  -x, --extensive       Search not only by the file extension, but also by the
                        file signature.
  -m, --malicious       Check if the file contains malicous macros or not. (A
                        lot of false positives)
```
