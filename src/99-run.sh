# Run main function only when executed directly (allows `source script.sh` in unit tests)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
