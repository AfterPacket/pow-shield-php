# PoW gateway image

Your `__ab/pow.php` references this default image path:

`/assets/img/clank.jpg`

To use it as-is:
- place an image at `assets/img/clank.jpg` in your webroot.

To use a different name/path:
- edit `__ab/pow.php` and change:

`$MEME_SRC = '/assets/img/clank.jpg';`
