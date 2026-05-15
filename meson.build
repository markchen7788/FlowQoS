#
# Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('DOCA_SAMPLE', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'),
		files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

SAMPLE_NAME = 'flowQoS'

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

sample_dependencies = []
# Required for all DOCA programs
sample_dependencies += dependency('doca-common')
# Library needed for this sample
sample_dependencies += dependency('doca-flow')
# Library used by the main() function
sample_dependencies += dependency('doca-argp')
# 3rd Party dependencies
sample_dependencies += dependency('libdpdk')

path='./src/'
sample_srcs = [
	# The sample itself
	path + SAMPLE_NAME + '_env.c',
	path + SAMPLE_NAME + '_pipe.c',
	path + SAMPLE_NAME + '_worker.c',
	path + SAMPLE_NAME + '_cmd.c',
	path + SAMPLE_NAME + '_router.c',
	path + SAMPLE_NAME + '_conntrack.c',
	path + SAMPLE_NAME + '_timer.c',
	path + SAMPLE_NAME + '_qos.c',
	path + SAMPLE_NAME + '_message.c',
	# Main function for the sample's executable
	# Common code for the DOCA library samples
	# Common code for all DOCA applications
	path + 'common/src/dpdk_utils.c',
	path + 'common/src/offload_rules.c',
]

sample_inc_dirs  = []
# Common DOCA library logic
sample_inc_dirs += include_directories(path)
# Common DOCA logic (applications)
sample_inc_dirs += include_directories(path+'common/src')

executable(SAMPLE_NAME + '_adaptive_routing', sample_srcs+'./apps/flowQoS_adaptive_routing.c',
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)

executable(SAMPLE_NAME + '_vxlan_packets_spraying', sample_srcs+'./apps/flowQoS_vxlan_packets_spraying.c',
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)

executable(SAMPLE_NAME + '_l4_load_balancing', sample_srcs+'./apps/flowQoS_l4_load_balancing.c',
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)

executable(SAMPLE_NAME + '_firewall', sample_srcs+'./apps/flowQoS_firewall.c',
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)

executable(SAMPLE_NAME + '_snat', sample_srcs+'./apps/flowQoS_snat.c',
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)
