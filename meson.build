#
# Meson build file for nvcrypttools
#
project('nvcrypttools', 'c')

libnvaes_sources = []

libnvaes_sources += 'nvaes.c'
libnvaes_sources += 'nvrcm.c'

libnvaes = static_library('nvaes', libnvaes_sources)

executable('nvencrypt', 'nvencrypt.c', link_with: [libnvaes], install: true)
executable('nvdecrypt', 'nvdecrypt.c', link_with: [libnvaes], install: true)
executable('nvsign', 'nvsign.c', link_with: [libnvaes], install: true)

