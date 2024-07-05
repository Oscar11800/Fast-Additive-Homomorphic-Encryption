import pytest
import test_additivity2c
from test_additivity2c import run_preset
from test_additivity2c import PresetTests

class TestFAHE1:
    
    def test_print_preset(self):
       print(run_preset(PresetTests.FAHE1_MINIMUM))
       
    def test_print_preset(self):
       print(run_preset(PresetTests.TEST2))
       
    def test_print_preset(self):
       print(run_preset(PresetTests.TEST3))
       
    def test_print_preset(self):
       print(run_preset(PresetTests.TEST4))
       