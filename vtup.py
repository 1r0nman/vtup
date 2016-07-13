from os import listdir
from os.path import isfile, join
import os
import time
import thread
import virustotal
import concurrent.futures
from filelock import FileLock
import threading

max_time=61
tresshold=1

def write_to_file(f):
    lock.acquire() # thread blocks at this line until it can obtain lock
	string = f+'\n'
    with open("found_potential_malware.txt", "a") as myfile:
        myfile.write(string)
    lock.release()


def vscan(f):
    start_time = time.time()
    report = v.scan(f, reanalyze=False)
    print f
    print "- Permalink:", report.permalink
    print "- Resource's MD5:", report.md5
    print "- Antivirus' total:", report.total
    print "- Antivirus's positives:", report.positives
    report.join()
    assert report.done == True
    for antivirus, malware in report:
        if malware is not None:
            print f
            print "Antivirus' total:", report.total
            print "Permalink:", report.permalink
            print "Antivirus:", antivirus[0]
            print "Antivirus' version:", antivirus[1]
            print "Antivirus' update:", antivirus[2]
            print "Malware:", malware
            #fl = open("results.txt", 'a+')
			if report.total > tresshold:
				write_to_file(f)
    while (time.time() - start_time) < max_time:
        time.sleep(5)


if __name__ == "__main__":
    v = virustotal.VirusTotal('e78dfc5da052ec9f818111ac84f4ab6eec37ebcefd215ff9314ffb592329b48e')
    lock = threading.Lock()
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        fs = [executor.submit(vscan, file) for file in files]
        concurrent.futures.wait(fs)