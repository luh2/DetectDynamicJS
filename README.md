# DetectDynamicJS Burp Extension

The DetectDynamicJS Burp Extension provides an additional passive scanner that tries to find differing content in JavaScript files and aid in finding user/session data.

Dynamically Generated JavaScript occasionally contains *data* in addition to code. Since, by default, scripts need to be able to be included by third parties, this can lead to leakage. The whole process of how to exploit this behavior is detailed in the paper [The Unexpected Dangers of Dynamic JavaScript](https://www.kittenpics.org/wp-content/uploads/2015/05/script-leakage.pdf) by Sebastian Lekies, Ben Stock, Martin Wentzel and Martin Johns. The paper inspired this extension. I hope this extension will ease the hunt for vulnerabilities described in the aforementioned paper. <!-- Release statement with additional information about the extension can be found on the official website [http://www.scip.ch/en/?labs.20151215](http://www.scip.ch/en/?labs.20151215).-->

## Requirements
This plugin requires Jython 2.7 and Python difflib, which is included in most Python environments. See heading [Python Environment](http://portswigger.net/burp/help/extender.html) in the official documentation of Burp. 

Some default installations of Python might not install difflib. In that case you need to download difflib from the official sites and specify its location in Burp->Extender->Options->Python Environment "Folder for loading modules". 

## Screenshots
![Screenshot of Issue](https://github.com/luh2/DetectDynamicJS/blob/master/screenshots/generic.png)
![Marked Difference in compared JS](https://github.com/luh2/DetectDynamicJS/blob/master/screenshots/secret.png)

## Various
The extension has been tested with Kali Linux, Burp version 1.6.32 and newer, Jython installation (not stand-alone) 2.7rc1.

If you test under Windows or use a different Burp version, please share if you experience problems.

If you want to improve the extension, please send me a pull request or leave a comment.

If you identify XSSI because of this extension, feel free to share!

## License
This software is released under [GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html).
