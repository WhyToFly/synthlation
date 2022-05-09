# Synthlation
Class project for CS 393P - Program Synthesis: "Stochastic Binary Translation"

Heavily inspired by the paper [Stochastic Superoptimization](https://theory.stanford.edu/~aiken/publications/papers/asplos13.pdf) (Schkufza, Sharma, Aiken)

## What this does

The program takes a compiled Game Boy ROM as an input and emulates it.

It runs test cases for a small part of the program and saves the results.

It then uses MCMC sampling to optimize program proposals until an equivalent x86 assembly program is found.


## Installation

Clone this repo
```
git clone https://github.com/WhyToFly/synthlation.git
cd synthlation
```

Clone modified version of [Baekalfen's](https://github.com/Baekalfen) PyBoy Game Boy Emulator and install it
```
git clone https://github.com/WhyToFly/PyBoy.git
cd PyBoy
pip install -r requirements.txt
python setup.py build_ext --inplace
pip install .
cd ..
```

Install assembly and emulation modules
```
pip install keystone-engine capstone unicorn
```

## Running

Run the synth script with the program you want to synthesize (from the /gb_programs/ directory) as an input

e.g. for the "add" program (adds the two input values)
```
python synth.py add
```
