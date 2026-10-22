"""Quiet 1080 recovery: D4 mechanism with R2 blank VI and no diagnostic renderer.

Keep original bounded waits and final idle check. Removing diagnostic pauses
changes timing, so the physical D4 success does not approve this variant yet.
"""
import build_three_games_candidate as C
from return_recovery_1080 import recovery_runtime,EXTRA,PROFILES

def build_runtime(debug=False,bt_no_igr=False):
 assert not debug and not bt_no_igr
 return recovery_runtime()

def cave():return C.cave(build_runtime,EXTRA,PROFILES)
def main(src,dst):return C.main(src,dst,build_runtime,EXTRA,PROFILES)
if __name__=='__main__':
 import sys
 main(*sys.argv[1:])
