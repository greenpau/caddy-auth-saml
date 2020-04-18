set -e

printf "Generating default UI template\n"
OUTPUT_FILE=ui_template.go
printf "package saml\n\nvar defaultUserInterface = \`" > ${OUTPUT_FILE}
cat assets/ui/ui.template >> ${OUTPUT_FILE}
printf "\`\n" >> ${OUTPUT_FILE}

