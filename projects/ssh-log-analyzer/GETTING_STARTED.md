# First Run in VS Code

The goal of this first lesson is to run the program, understand its counters,
and make a controlled change to the bundled synthetic data.

## 1. Open the project

If the repository is not cloned yet, run these commands in a Linux terminal:

```bash
git clone https://github.com/Nodir404/Cyber-Learning.git
cd Cyber-Learning
code .
```

If it is already cloned, open its folder in VS Code, open the integrated
terminal, and check for local changes:

```bash
git status --short
```

If any paths are listed, stop and review them before switching branches.
Otherwise, update the main branch:

```bash
git switch main
git pull --ff-only origin main
```

If the `code` command is unavailable, open VS Code normally and choose
File → Open Folder → Cyber-Learning.

## 2. Run the example

From the repository root, run:

```bash
python3 --version
cd projects/ssh-log-analyzer
python3 analyzer.py data/sample_auth.log --csv report.csv
```

Python 3.10 or newer is required. The expected result is **3 successful
logins, 4 failed logins, 4 IP addresses, and 3 skipped lines**. A `report.csv`
file will appear in the project directory. The records are synthetic and are
intended for experimentation.

## 3. Inspect one record

Open `data/sample_auth.log`. Find the line containing `Failed password`, the
address `192.0.2.10`, and the user `admin`. In `analyzer.py`, review
`parse_line()` and `analyze()` and trace:

1. How is the `(IP, result)` pair extracted from the text?
2. Why is the IP address validated with `ipaddress`?
3. Where are the two counters created for a new address?
4. Which line increments the appropriate counter?

## 4. Run an experiment

Append one more `Failed password` line for `192.0.2.10` to the sample log,
changing the timestamp and process number. Predict the new results before
running the program. Run it again and verify that failed attempts increase to
**5** while the number of unique IP addresses remains **4**.

Then remove the added line and save the file to restore the original example.
Run the tests:

```bash
python3 -m unittest -v
```

## Next task

Add a percentage for failed attempts:

```text
failed / (success + failed) * 100
```

The original example should produce approximately **57.1%**. An empty log must
not cause division by zero. This is the next small step after the first run.

Continue with the [burst detection lesson in Russian](LESSON_02_RU.md) to
investigate frequent failed attempts within a rolling time window.
