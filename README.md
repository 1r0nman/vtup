Vtup provides automatic way of uploading files to VT for scanning.

VT limits malware sample scanning up to 4 samples for free accounts.

VT was created to scan exactly 4 samples in a minute.

USAGE:

Just copy to the catalogue where are the files to be scanned.

Then run it without any parameters:
python vtup.py

ADDITIONAL INFO:

You can set a number of positive detection for saving name of a sample to file.
Default value is 2, so if there are two positive detections filename will be saved to a file "found_potential_malware.txt"
You edit this by modyfying tresshold value.
