
function(find_xcframework VAR XFWK_PATH)
    # 1. 检查输入的 xcframework 路径
    if(NOT EXISTS "${XFWK_PATH}")
        message(FATAL_ERROR "[find_xcframework] Path does not exist: ${XFWK_PATH}")
    endif()

    # 2. 判断当前目标是 iOS 真机还是模拟器
    if(CMAKE_OSX_SYSROOT MATCHES "iphonesimulator")
        set(_IS_SIMULATOR TRUE)
    else()
        set(_IS_SIMULATOR FALSE)
    endif()

    # 3. 列出 xcframework 下的所有子目录
    file(GLOB _ALL_SUBDIRS RELATIVE "${XFWK_PATH}" "${XFWK_PATH}/*")

    set(_MATCHED_SUBDIR "")

    foreach(_SUBDIR IN LISTS _ALL_SUBDIRS)
        # 排除 Info.plist 或非目录项
        if(IS_DIRECTORY "${XFWK_PATH}/${_SUBDIR}")
            string(TOLOWER "${_SUBDIR}" _SUBDIR_LOWER)

            if(_IS_SIMULATOR)
                # 模拟器场景：目录名必须包含 "simulator"
                if(_SUBDIR_LOWER MATCHES "simulator")
                    set(_MATCHED_SUBDIR "${_SUBDIR}")
                    break()
                endif()
            else()
                # 真机场景：目录名包含 "ios" 或 "iphone"，但绝对不能包含 "simulator"
                if((_SUBDIR_LOWER MATCHES "ios" OR _SUBDIR_LOWER MATCHES "iphone")
                   AND NOT _SUBDIR_LOWER MATCHES "simulator")
                    set(_MATCHED_SUBDIR "${_SUBDIR}")
                    break()
                endif()
            endif()
        endif()
    endforeach()

    # 4. 如果上面的通配规则没命中，尝试保底逻辑（匹配非 plist 的第一个有效目录）
    if(NOT _MATCHED_SUBDIR)
        foreach(_SUBDIR IN LISTS _ALL_SUBDIRS)
            if(IS_DIRECTORY "${XFWK_PATH}/${_SUBDIR}")
                string(TOLOWER "${_SUBDIR}" _SUBDIR_LOWER)
                if(_IS_SIMULATOR AND _SUBDIR_LOWER MATCHES "simulator")
                    set(_MATCHED_SUBDIR "${_SUBDIR}")
                    break()
                elseif(NOT _IS_SIMULATOR AND NOT _SUBDIR_LOWER MATCHES "simulator")
                    set(_MATCHED_SUBDIR "${_SUBDIR}")
                    break()
                endif()
            endif()
        endforeach()
    endif()

    if(NOT _MATCHED_SUBDIR)
        message(FATAL_ERROR "[find_xcframework] Failed to find a matching slice in ${XFWK_PATH} for "
                            "${CMAKE_OSX_SYSROOT} (Is Simulator: ${_IS_SIMULATOR})")
    endif()

    # 5. 拼接找到的内部平台路径
    set(_INNER_PATH "${XFWK_PATH}/${_MATCHED_SUBDIR}")
    get_filename_component(_XFWK_NAME "${XFWK_PATH}" NAME_WE)

    # 6. 识别内部结构并生成编译/链接参数
    if(EXISTS "${_INNER_PATH}/${_XFWK_NAME}.framework")
        # 结构 A: 标准 .framework 结构
        set(${VAR}_CFLAGS "-F${_INNER_PATH}" PARENT_SCOPE)
        set(${VAR}_LFLAGS "-F${_INNER_PATH} -framework ${_XFWK_NAME}" PARENT_SCOPE)

    elseif(EXISTS "${_INNER_PATH}/Headers")
        # 结构 B: .a 静态库 + Headers 结构
        file(GLOB _STATIC_LIBS "${_INNER_PATH}/*.a")
        list(GET _STATIC_LIBS 0 _LIB_FILE)

        set(${VAR}_CFLAGS "-I${_INNER_PATH}/Headers" PARENT_SCOPE)
        set(${VAR}_LFLAGS "${_LIB_FILE}" PARENT_SCOPE)

    else()
        message(FATAL_ERROR "[find_xcframework] Found slice folder '${_MATCHED_SUBDIR}' but no .framework or Headers directory exists inside.")
    endif()
endfunction()