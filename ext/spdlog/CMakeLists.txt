
Include(FetchContent)

FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog
        GIT_TAG v1.14.0
        EXCLUDE_FROM_ALL
)

FetchContent_MakeAvailable(spdlog)
