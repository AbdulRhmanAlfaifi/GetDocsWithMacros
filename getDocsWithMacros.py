"""
Developed By AbdulRhman Hussin Alfaifi. (Twitter @A__Alfaifi)
"""
from prettytable import PrettyTable
from oletools.olevba import *
import json
import hashlib
import argparse
import platform
import os
import shutil
import math
import oletools.oleid


parser = argparse.ArgumentParser(description='Collect all doc File that has macros.')
parser.add_argument('-sd','--StartingDirectory',default=("C:\\" if "Windows" in platform.system() else "/"),help='The starting directory from where the script will start searching. Default is C:\\ for windows or / for linux')
parser.add_argument("-c","--copy",action='store_true',help='Copy the detected doc files to [CurrentDir]/DOCs.')
parser.add_argument("-o","--output",dest="outputFile",default=None,help="Output the results to the spicified file with CSV formate.")
parser.add_argument("-ha","--hash",dest="hashAlg",default="md5",help="Which hashing algorithm to use (MD5 or SHA1) default is md5.",choices=['md5','sha1'])
parser.add_argument("-x","--extensive",dest="fs",action='store_true',help="Search not only by the file extension, but also by the file signature.")
parser.add_argument("-m","--malicious",dest="mal",action='store_true',help="Check if the file contains malicous macros or not. (A lot of false positives)")

args = parser.parse_args()

# Manage the printing of the results.
def printResults(paths,outputFile=None):
	if outputFile == None:
		if len(paths) == 0:
			print("Could not find any file with macros.")
			return
		table = PrettyTable(encoding="windows-1256")
		if args.hashAlg == "md5":
			if args.mal:
				table.field_names = ["File Name", "File Path", "Hash (MD5)", "Malicious?"]
			else:
				table.field_names = ["File Name", "File Path", "Hash (MD5)"]
		else:
			if args.mal:
				table.field_names = ["File Name", "File Path", "Hash (SHA1)", "Malicious?"]
			else:
				table.field_names = ["File Name", "File Path", "Hash (SHA1)"]
		for path in paths:
			if args.mal:
				table.add_row([path.split(os.sep)[-1],path,md5(path) if args.hashAlg == "md5" else sha1(path),HasMaliciousMacros(path)])
			else:
				table.add_row([path.split(os.sep)[-1],path,md5(path) if args.hashAlg == "md5" else sha1(path)])
		print(table)
	else:
		outFile = open(outputFile,"w")
		# outFile.write("Name,Path,Hash (SHA1)\n")
		for path in paths:
			if args.hashAlg == "sha1":
				if args.mal:
					outLine = path.split(os.sep)[-1]+","+path+","+sha1(path)+","+str(HasMaliciousMacros(path))+"\n"
				else:
					outLine = path.split(os.sep)[-1]+","+path+","+sha1(path)+"\n"
			else:
				if args.mal:
					outLine = path.split(os.sep)[-1]+","+path+","+md5(path)+","+str(HasMaliciousMacros(path))+"\n"
				else:
					outLine = path.split(os.sep)[-1]+","+path+","+md5(path)+"\n"
			outFile.write(outLine)


# Check if the doc file hash malicious macros.
def HasMaliciousMacros(pathToDoc):
	vbaparser = VBA_Parser(pathToDoc)
	vbaparser.analyze_macros()
	if vbaparser.nb_autoexec > 0:
		return True
	indecators = vbaparser.nb_suspicious + vbaparser.nb_iocs + vbaparser.nb_hexstrings + vbaparser.nb_base64strings + vbaparser.nb_dridexstrings + vbaparser.nb_vbastrings
	if indecators > 3:
		return True
	else:
		return False

# Get SHA1 hash for a file.
def sha1(fname):
    hash_sha1 = hashlib.sha1()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

# Get MD5 hash for a file.
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()



# Check if the file specified has macros.
def DoesDocHasMacro(pathToDoc):
	try:
		vbaparser = VBA_Parser(pathToDoc)
		if vbaparser.detect_vba_macros():
			return True
		else:
			return False
	except:
		return False


# Check if the file specified hash embeded flash object.
def DoesDocHasFlashObj(pathToDoc):
	# TODO: implement this function
	return False



# Check if the file specified is a doc file.
def isDocFile(pathToDoc):
	try:
		extension = pathToDoc[pathToDoc.rfind(".")+1::]
		listOfExtentions = ["doc","xls","ppt","docx","xlsx","pptx","docm"]
		if extension in listOfExtentions:
			return True

		if args.fs:
			filesig = ""
			file = open(pathToDoc,"rb")
			for i in range(8):
				filesig += hex(ord(file.read(1))).replace("0x","")
			if filesig[0:8] == "504b0506" or filesig[0:8] == "504b0304" or filesig[0:8] == "504b0708" or filesig == "d0cf11e0a1b11ae1":
				return True
			else:
				return False
		else:
			return False
	except:
		return False

docFilesWithMacros = []

for subdir, dirs, files in os.walk(os.path.abspath(args.StartingDirectory)):
	for file in files:
		filepath = os.path.join(subdir, file)
		filepath = filepath.replace("\\\\","\\")
		if isDocFile(filepath):
			if DoesDocHasMacro(filepath):
				docFilesWithMacros.append(filepath)
				if args.copy:
					if os.path.isdir("."+os.sep+"DOCs"):
						shutil.copy(filepath,"."+os.sep+"DOCs")
					else:
						os.mkdir("."+os.sep+"DOCs")
						shutil.copy(filepath,"."+os.sep+"DOCs")

printResults(docFilesWithMacros,args.outputFile)
