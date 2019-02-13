#
# Meson build file for nvcrypttools
#
project('nvcrypttools', 'c')

libnvaes_sources = []

libnvaes_sources += 'nvaes.c'
libnvaes_sources += 'nvrcm.c'

libnvaes = static_library('nvaes', libnvaes_sources)

executable('nvencrypt', 'nvencrypt.c', link_with: [libnvaes])
executable('nvdecrypt', 'nvdecrypt.c', link_with: [libnvaes])
executable('nvsign', 'nvsign.c', link_with: [libnvaes])
