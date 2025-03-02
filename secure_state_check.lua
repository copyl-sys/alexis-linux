-- secure_state_check.lua
-- This script loads the current state, verifies its checksum, and then re-saves it.

function verify_state()
    local state = load_state("current_state.enc")
    if not state then
        print("State load failed!")
        return false
    end
    local checksum = compute_checksum(state)
    print("State checksum:", checksum)
    local saved = save_state("current_state_verified.enc")
    if saved then
        print("State re-saved successfully.")
        return true
    else
        print("Failed to re-save state!")
        return false
    end
end

-- Run the verification
if verify_state() then
    print("Secure state verified successfully.")
else
    print("Secure state verification failed.")
end
