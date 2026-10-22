"""Exact-revision Tag Anywhere binding, retaining original three-game paths."""
import sys
import build_three_games_candidate as C
EXTRA={'dk64':[(0x444f4500,0x77303ba3,0xc2838723)]}
def cave():return C.cave(extra_headers=EXTRA)
def main(src,dst):return C.main(src,dst,extra_headers=EXTRA)
if __name__=='__main__':main(*sys.argv[1:])
