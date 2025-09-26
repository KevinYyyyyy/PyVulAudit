#!/bin/bash

pkgs=$(find ../docker_workdir/pypi_packages -mindepth 2 -maxdepth 2 -type d | wc -l)
cg_files=$(find ../data_collection/call_graphs -mindepth 2 -maxdepth 3 -type f ! -name "ERROR" | wc -l)
cg_files_errors=$(find ../data_collection/call_graphs -mindepth 2 -maxdepth 3  -type f -name "ERROR"| wc -l)

install_errors=$(find ../docker_workdir/pypi_packages -mindepth 2 -maxdepth 3 -type f -name "HAVEERROR" | wc -l)+$(find ../docker_workdir/pypi_packages -mindepth 2 -maxdepth 3 -type f -name "ERROR" | wc -l)
pyvers=$(find ../docker_workdir/pypi_packages -mindepth 2 -maxdepth 3 -type f -name "INSTALLED_PY_VERSION" | wc -l)
# 查找出现在pkgs但未在install_errors中的包


printf "Total Packages:\t\t%d\n" $pkgs

printf "Installed Py Versions:\t%d\n" $pyvers
printf "Error Flags:\t\t%d\n" $install_errors

printf "\n"
printf "Successful CG Files:\t%d\n" $cg_files
printf "Error CG Files:\t%d\n" $cg_files_errors

pypi_pkgs=$(find ../docker_workdir/pypi_packages -mindepth 2 -maxdepth 2 -type d | sed 's|../docker_workdir/pypi_packages/||' | sort)
cg_pkgs=$(find ../data_collection/call_graphs -mindepth 2 -maxdepth 2 -type d | sed 's|../data_collection/call_graphs/||' | sort)
diff_count=$(comm -23 <(echo "$pypi_pkgs") <(echo "$cg_pkgs") | wc -l)
printf "Packages without call graphs:\t%d\n" $diff_count
printf "\n"


# find ../docker_workdir/pypi_packages -mindepth 2 -maxdepth 2 -type d | while read pkg; do
#     if ! find "$pkg" -mindepth 1 -maxdepth 2 -type f -name "HAVEERROR" -o -name "ERROR" -o -name "INSTALLED_PY_VERSION" | grep -q .; then
#         echo "$pkg"
#     fi
# done



