# Intune
Scripts for MS Intune

Proactive Remediation Scripts:

/BranchCache Tuner (MAIN) contains the detect and remediation script to check a bunch of BranchCache config settings namely:
Checks for events indicating that the Firewall is blocking BC incoming/outgoing discovery or content
Checks the output of NETSH.EXE for other clues to misconfiguration
Checks the default Portas that BC uses (and URL reservation)
Checks the 'Server peers on battery' setting
Checks the 'Cache TTL' paramter (this is the number of days that BC will retain content)
Checks that the BC service is set to autostart

If ANY of the above checks fails we exit and run the remediation script.

The remediation script sets all of the above settings to their correct parameters.

You might want to change the default settings within the script, so have a read of the scripts and test in your own environment to determjine the optimal settings for you!


/BranchCache Tuner (CACHE) contains the detect and remediation script to check that the BranchCache cache size is set to the correct size.
If the cache size needs changing (incorrect size discovered) the remediation script will set a new cache size.
As ever, check the settings within the script and change them to suit your own preferences.


IMPORTANT:
When you create the Proactive Remediation in EndPoint Analytics, remember to flip the 'Run script in 64-bit PowerShell' switch ;)

