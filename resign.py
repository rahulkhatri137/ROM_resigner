from xml.dom import minidom
import re, os, mmap, subprocess, fnmatch, argparse, fileinput

cwd = os.path.dirname(os.path.realpath(__file__))

def find(pattern, path):
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                return os.path.join(root, name)


parser = argparse.ArgumentParser(description="Python Script to resign an Android ROM using custom keys")
parser.add_argument('RomDir', help='ROM Path')
parser.add_argument('SecurityDir', help='Security Dir Path (just like https://android.googlesource.com/platform/build/+/master/target/product/security/)')
args = parser.parse_args()
romdir = args.RomDir
securitydir = args.SecurityDir

mac_permissions = find("*mac_permissions*", f"{romdir}/etc/selinux")

xmldoc = minidom.parse(mac_permissions)
itemlist = xmldoc.getElementsByTagName('signer')
certlen = len(itemlist)

signatures = []
signatures64 = []
seinfos = []
usedseinfos = []

tmpdir = f"{cwd}/tmp"
signapkjar = f"{cwd}/signapk.jar"
os_info = os.uname()[0]
signapklibs = f"{cwd}/{os_info}"

def CheckCert(filetoopen, cert):
    f = open(filetoopen)
    s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    return s.find(cert) != -1

def getcert(jar, out):
    extractjar = f"7z e {jar} META-INF/CERT.RSA -o{tmpdir}"
    output = subprocess.check_output(['bash','-c', extractjar])

    if os.path.exists(f"{tmpdir}/CERT.RSA"):
        extractcert = f"openssl pkcs7 -in {tmpdir}/CERT.RSA -print_certs -inform DER -out {out}"

        output = subprocess.check_output(['bash','-c', extractcert])
        os.remove(f"{tmpdir}/CERT.RSA")

    #print(output)

def sign(jar, certtype):
    if not os.path.exists(f"{securitydir}/{certtype}.pk8"):
        print(f"{certtype}.pk8 not found in security dir")
        return False

    jartmpdir = f"{tmpdir}/JARTMP"
    if not os.path.exists(jartmpdir):
        os.makedirs(jartmpdir)

    signjarcmd = f"java -XX:+UseCompressedOops -Xms2g -Xmx2g -Djava.library.path={signapklibs} -jar {signapkjar} {securitydir}/{certtype}.x509.pem {securitydir}/{certtype}.pk8 {jar} {jartmpdir}/{os.path.basename(jar)}"


    movecmd = f"mv -f {jartmpdir}/{os.path.basename(jar)} {jar}"
    try:
        output = subprocess.check_output(['bash','-c', signjarcmd])
        output += subprocess.check_output(['bash','-c', movecmd])
        #print(output)
        print(f"{os.path.basename(jar)} signed as {seinfo}")
        usedseinfos.append(seinfo) if seinfo not in usedseinfos else usedseinfos
    except subprocess.CalledProcessError:
        print(f"Signing {os.path.basename(jar)} failed")

index = 0
for s in itemlist:
    signatures.append(s.attributes['signature'].value)
    test64 = s.attributes['signature'].value.decode("hex").encode("base64")
    test64 = test64.decode('utf-8').replace('\n', '')
    
    signatures64.append(re.sub("(.{64})", "\\1\n", test64, 0, re.DOTALL))

    seinfos.append(xmldoc.getElementsByTagName('seinfo')[index].attributes['value'].value)
    index += 1

for root, dirs, files in os.walk(romdir):
    for file in files:
        if file.endswith(".apk") or file.endswith(".jar") or file.endswith(".apex"):
            jarfile=os.path.join(root, file)
            
            if not os.path.exists(tmpdir):
                os.makedirs(tmpdir)
            os.chdir(tmpdir)
            
            out = "foo.cer"
            if os.path.exists(out):
                os.remove(out)
            
            getcert(jarfile, out)
            if not os.path.exists(out):
                print(file + " : No Siganture => Skip")
            else:
                index = 0
                for seinfo in seinfos:
                    if CheckCert(out, signatures64[index]):
                        sign(jarfile, seinfo)
                        break
                    index += 1
                if index == certlen:
                        print(file + " : Unknown => keeping signature")

index = 0
for s in itemlist:
    oldsignature = s.attributes['signature'].value
    seinfo = xmldoc.getElementsByTagName('seinfo')[index].attributes['value'].value
    index += 1
    if seinfo in usedseinfos:
        pemtoder = "openssl x509 -outform der -in " + securitydir + "/" + seinfo + ".x509.pem"
        output = subprocess.check_output(['bash','-c', pemtoder])
        newsignature = output.encode("hex")
        for line in fileinput.input(mac_permissions, inplace=True):
            print line.replace(oldsignature, newsignature),
