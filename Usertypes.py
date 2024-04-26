from enum import IntEnum


class BinningOption(IntEnum):
    """
    BinningOption is an enumeration class that represents different binning options.

    Attributes
    ----------
    NONE : int
        Represents no binning option.
    TWO_BY_TWO : int
        Represents the 2x2 binning option.
    FOUR_BY_FOUR : int
        Represents the 4x4 binning option.
    """
    NONE = 0
    TWO_BY_TWO = 1
    FOUR_BY_FOUR = 2


class AcquisitionModeStereo(IntEnum):
    """
    This class represents the acquisition mode of the stereo front end. 
    It provides three modes: NORMAL, HDR, and HQM.

    Attributes:
        NORMAL (int): The standard acquisition mode.
        HDR (int): This mode is recommended when both dark and shiny objects are present in the scene. 
                    Two different integration times can be defined by the user to handle scenes of such high dynamic range.
        HQM (int): The high quality mode (HQM) will increase the repeatability of your depth values but may reduce the frame rate.
    """
    NORMAL = 0  # normal mode
    HDR = 1  # high dynamic range mode
    HQM = 2  # high quality mode


class ThreeLevels(IntEnum):
    """
    This class is a representation of the Usertype `ThreeLevels`.
    Each level defines a level of severity: `INVALID`, `ERROR`, `WARNING`, and `GOOD`.
    This usertype is the defined return type for the variables `OpVoltageStatus` and `TempLevel`.

    Attributes:
        INVALID (int): Represents an invalid condition.
        ERROR (int): Represents a condition where an error has occurred.
        WARNING (int): Represents a condition that may lead to an error if not addressed.
        GOOD (int): Represents a condition that is functioning as expected.
    """
    INVALID = 0
    ERROR = 1
    WARNING = 2
    GOOD = 3


class FrontendMode(IntEnum):
    """
    This class is a representation of the `FrontendMode` Usertype.
    Each mode defines a state of the frontend: `eContinuous`, `eStopped`, and `eExternalTrigger`.

    Attributes:
        eContinuous (int): Represents a state where image acquisition is continuous.
        eStopped (int): Represents a state where the frontend is stopped, but snapshots can be triggered.
        eExternalTrigger (int): Represents a state where an external trigger signal is required to acquire images.
    """
    Continuous = 0
    Stopped = 1
    ExternalTrigger = 2


class InputFunctionType(IntEnum):
    """
    This class is a representation of the `InputFunctionType` Usertype.
    Each mode defines a different type of input function: `NoFunction`, `PowerSaveMode`, `Trigger`, `JobSwitching`, and `JobCycling`.

    Attributes:
        NoFunction (int): No function is assigned.
        PowerSaveMode (int): Represents a state where the power save mode is activated.
        Trigger (int): Represents a state where a trigger signal is required.
        JobSwitching (int): Represents a state where job switching is enabled.
        JobCycling (int): Represents a state where job cycling is enabled.
    """
    NoFunction = 0
    PowerSaveMode = 1
    Trigger = 2
    JobSwitching = 4
    JobCycling = 5


class IOFunctionType(IntEnum):
    """
    This class is a representation of the `IOFunctionType` Usertype.
    Each mode defines a different type of IO function.

    Attributes:
        NoFunction (int): No function is assigned.
        SteadyLOW (int): Output is steady low.
        SteadyHIGH (int): Output is steady high.
        DeviceStatus (int): Represents a state where the device status is indicated.
        DataQualityCheck (int): Represents a state where data quality is checked.
        TemperatureWarning (int): State where a temperature warning is issued.
        Trigger (int): Represents a state where a trigger signal is required.
        TriggerBusy (int): Represents a state where the trigger is busy.
        PowerSaveMode (int): Represents a state where the power save mode is activated.
        JobSwitching (int): Represents a state where job switching is enabled.
        IlluminationTrigger (int): Used to trigger an external illumination.
        HeartbeatOut (int): Used to output a device-alive heartbeat signal.
    """
    NoFunction = 0
    SteadyLOW = 1
    SteadyHIGH = 2
    DeviceStatus = 3
    DataQualityCheck = 4
    TemperatureWarning = 5
    Trigger = 7
    TriggerBusy = 23
    PowerSaveMode = 24
    JobSwitching = 25
    IlluminationTrigger = 28
    HeartbeatOut = 29


class UserLevel(IntEnum):
    """
    Enum representing different user levels in visionary devices.
    The ability of a user to write a variable or execute a method depends on their user level
    """
    Run = 0
    Operator = 1
    Maintenance = 2
    AuthorizedClient = 3
    Service = 4
