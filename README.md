# DetectDynamicJS Burp Extension

The DetectDynamicJS Burp Extension provides an additional passive scanner that tries to find differing content in JavaScript files, based on removal of ambient authority information and aid in finding user/session data.

Dynamically Generated JavaScript occasionally contains *data* in addition to code. Since, by default, scripts need to be able to be included by third parties, this can lead to leakage. For more information about the reasons, the ways to find or how to exploit this issue, see [Cross-Site Script Inclusion](http://www.scip.ch/en/?labs.20160414). For those that prefer to watch, there is a presentation from [Security Fest 2016](https://www.youtube.com/watch?v=5qA0CtS6cZ4).

## Requirements
This plugin requires Jython 2.7 and Python difflib, which is included in most Python environments. See heading [Python Environment](http://portswigger.net/burp/help/extender.html) in the official documentation of Burp. 

Some default installations of Python might not install difflib. In that case you need to download difflib from the official sites and specify its location in Burp->Extender->Options->Python Environment "Folder for loading modules". 

## Screenshots
![Screenshot of Issue](https://github.com/luh2/DetectDynamicJS/blob/master/screenshots/generic.png)
![Marked Difference in compared JS](https://github.com/luh2/DetectDynamicJS/blob/master/screenshots/secret.png)

## Contributions
If you want to improve the extension, please send me a pull request or open an issue. To ease accepting pull requests, if you send a pull request, please make sure it addresses only one change and not multiple ones at the same time.

## Various
The extension has been tested with Kali Linux, Burp version 1.6.32 and newer, Jython installation (not stand-alone) 2.7rc1.

If you test under Windows or use a different Burp version, please share if you experience problems.

If you identify XSSI because of this extension, feel free to share!

## Thanks to

1lastBr3ath, wh1tenoise and soffensive for contributing bug fixes and features.

## License
This software is released under [GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html).
