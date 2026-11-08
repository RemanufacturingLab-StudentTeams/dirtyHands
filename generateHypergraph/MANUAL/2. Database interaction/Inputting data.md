# Inputting data

To input data into the Reman Neo4j database, only two things are needed: a suitable excel file (in a valid format) and the data-input script.

## Navigating to this folder

Because every user inzips this document-package to a different location, it is necessary to navigate to this exact folder.

Open up a Command Line (Windows + R and type cmd) and write cd + the path to this folder.

For me personally this would look like:

```bash
cd C:\Users\niels\Documents\2026 Lectoraat SSM\2026 Dirty Hands 2.0\MANUAL\2. Database interaction
```

If done right, it should now be ready to type a command in at the location this manual lives in.

## Converting excel-file into Reman neo4j graph database

To then put the data from the excel file into the Reman server, we can simply run the following command:

```bash
python insert_data.py
```

Here it will ask for the excel file name. Make sure this excel is located in the same folder as the script!

If all goes well, it should print the messages that connections, parts and tiers have been inserted.

All notifications regarding NaN rows can be ignored.

