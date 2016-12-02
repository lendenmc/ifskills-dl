# Ifskills-dl

##  https://learn.infiniteskills.com training videos downloader
This is the 0.* version of the ifskills-dl command-line program. 
Given one or several course sku ids from your https://learn.infiniteskills.com registered account, it downloads all the video lectures associated with the corresponding courses, and stores them by section into a single course folder whose name is the course title.
This is a **Python 3** program. It has been tested under **Python 3.5.2** running on **OS X** El Capitan (10.11) or **macOS** Sierra (10.12).

## Usage
Once its dependencies are installed (see bellow), you run this version of the program with the command:
```
$ python ifskills-dl.py sku1 sku2 sku3
````
where `sku1`, `sku2`, ... represent the unique identifiers (let's say course ids) of each course you want to download. The course id is the value of the parameter `sku`of the url of a single course. For instance the course at https://learn.infiniteskills.com/product.html?sku=02196 has the id `02196`. This id is also explicitly displayed on the single course page.

The program will ask for your https://learn.infiniteskills.com credentials, i.e. your username and password. As it would be quickly tedious to enter your credentials on every occasion, you can create or add them to a `netrc` file under the 'machine' name `learn.infiniteskills.com`. The program automatically looks for them.

## Dependencies
Obviously, **you need to hold a registered Infinite Skills account** for this program to work.
From a programming standpoint, apart from **Python 3**, the following python third party libraries are required:
- **requests**
- **beautifulsoup4**

You can install these with:
```
$ pip install -r requirements.txt
```

## Download method
This version of the program runs **sequentially**, which means that it downloads one course after another, and one video lecture after another within each course. Right from the start, It will also download and unzip the course working files whenever they exist. It creates the directory structure of a course before starting to download each individual video lecture file.
If you relaunch the program after an interruption, the program will skip the download of the videos files that have been already downloaded. So **you can safely interrupt the course downloading process and start where you left off later on**.

## Directory structure of the downloaded files
For each course the program will create a main folder whose name is the title of the course, **in your current directory**. The course folder is then filled with subfolders created for each section of the course. Similarly, the section title provides the name of the section subfolder. Additionally, the unzipped folder of the course working files will be downloaded into the course directory. Finally each lecture video file will be downloaded into its corresponding section folder. As it turns out, each lecture corresponds to one video file, whose name is the lecture name.

## Installation
You can download and unzip the latest version zip file from the program's Github repository. However the only file this program actually needs to run is `ifskills-dl.py`.

Cheers !
