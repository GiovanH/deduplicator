from index import getDuplicates

files = [
    'F:\\Franchises\\Steven Universe\\Unsorted\\1527629538539.png',
    'F:\\Franchises\\Steven Universe\\Steven\\tumblr_owni2yeP8y1sl59avo3.png',
    'F:\\Franchises\\Steven Universe\\Amethyst\\tumblr_owni2yeP8y1sl59avo4_r1_1280.png',
    'F:\\Franchises\\Steven Universe\\Pearlification\\tumblr_owni2yeP8y1sl59avo4_r1_1280.png',
    'F:\\Franchises\\Steven Universe\\Unsorted\\1527629538539.png',
    'F:\\Franchises\\Steven Universe\\Pearl\\tumblr_owni2yeP8y1sl59avo3.png'
]

sort = (lambda x: (-x.lower().rfind("unsorted"), len(x)))
files = sorted(files, key=sort)
print("\n".join(["\t" + f for f in files]))
print()
print("\n".join(["\t" + f for f in getDuplicates(files)]))
