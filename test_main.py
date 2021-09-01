from features.numa import *
import pytest

#def setup():
    #Read Settings Files
    #Read Baremetsl Nodes List
    #Setup Environment
    
    #return settings

#def(tear_down):
#     Tear Down Data

@pytest.mark.numa
def test_addition():
    assert numa_add(2,6)== 8


@pytest.mark.hugepages
def test_addition():
    assert numa_add(2,6)==10